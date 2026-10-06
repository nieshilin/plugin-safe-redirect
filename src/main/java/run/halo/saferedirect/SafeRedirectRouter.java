package run.halo.saferedirect;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import run.halo.app.plugin.ReactiveSettingFetcher;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * 安全跳转路由处理器
 *
 * <p>处理两个端点：
 * <ul>
 *   <li>GET /plugins/plugin-safe-redirect/go — 渲染安全跳转中间页</li>
 *   <li>GET /plugins/plugin-safe-redirect/assets/** — 静态资源（由框架自动处理）</li>
 * </ul>
 *
 * @author SafeRedirect Team
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SafeRedirectRouter {

    private final ReactiveSettingFetcher settingFetcher;

    /**
     * 注册路由：/plugins/plugin-safe-redirect/go
     */
    public RouterFunction<ServerResponse> route() {
        return RouterFunctions.route()
            .GET("/plugins/plugin-safe-redirect/go", this::handleRedirect)
            .build();
    }

    /**
     * 处理安全跳转请求
     * <p>
     * 请求示例：/plugins/plugin-safe-redirect/go?url=https%3A%2F%2Fgithub.com
     */
    private Mono<ServerResponse> handleRedirect(ServerRequest request) {
        String rawUrl = request.queryParam("url").orElse("");

        if (rawUrl.isBlank()) {
            return ServerResponse.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue("<h1>缺少目标链接参数</h1>");
        }

        String targetUrl;
        try {
            targetUrl = URLDecoder.decode(rawUrl, StandardCharsets.UTF_8);
            // 安全校验：只允许 http/https 协议，防止 javascript: 等注入
            if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                log.warn("Blocked non-http redirect attempt to: {}", targetUrl);
                return ServerResponse.badRequest()
                    .contentType(MediaType.TEXT_HTML)
                    .bodyValue(buildErrorPage("非法链接", "只支持 HTTP/HTTPS 协议的外部链接跳转。"));
            }
        } catch (Exception e) {
            log.warn("Invalid URL encoding: {}", rawUrl);
            return ServerResponse.badRequest()
                .contentType(MediaType.TEXT_HTML)
                .bodyValue(buildErrorPage("链接格式错误", "无法解析目标链接，请检查链接是否正确。"));
        }

        final String finalUrl = targetUrl;

        return settingFetcher.fetch("basic", BasicSetting.class)
            .defaultIfEmpty(new BasicSetting())
            .flatMap(basicSetting -> {
                // 检查插件是否启用
                if (!basicSetting.isEnabled()) {
                    // 插件禁用时直接302重定向
                    return ServerResponse.temporaryRedirect(URI.create(finalUrl)).build();
                }

                // 检查白名单
                boolean whitelisted = WhitelistMatcher.isWhitelisted(finalUrl, basicSetting.getWhitelistDomains());
                if (whitelisted) {
                    log.debug("Whitelisted domain, direct redirect to: {}", finalUrl);
                    try {
                        return ServerResponse.temporaryRedirect(URI.create(finalUrl)).build();
                    } catch (Exception e) {
                        log.error("Failed to create redirect URI for whitelisted URL: {}", finalUrl, e);
                        // 如果白名单跳转失败，继续显示中间页
                    }
                }

                // 记录外链跳转（可选）
                return settingFetcher.fetch("advanced", AdvancedSetting.class)
                    .defaultIfEmpty(new AdvancedSetting())
                    .flatMap(advancedSetting -> {
                        if (advancedSetting.isTrackOutbound()) {
                            log.info("Outbound link accessed: {}", finalUrl);
                        }
                        return settingFetcher.fetch("style", StyleSetting.class)
                            .defaultIfEmpty(new StyleSetting())
                            .flatMap(styleSetting -> {
                                // 检查是否使用自定义 HTML
                                String customHtml = styleSetting.getCustomHtml();
                                if (customHtml != null && !customHtml.trim().isEmpty()) {
                                    // 使用自定义 HTML（完全替换整个页面）
                                    // 禁止缓存中间页，防止浏览器通过缓存/bfcache 回退显示过期页面
                                    return ServerResponse.ok()
                                        .contentType(MediaType.TEXT_HTML)
                                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                                        .bodyValue(buildCustomPage(finalUrl, basicSetting, customHtml.trim()));
                                }
                                // 使用默认模板
                                // 禁止缓存中间页，防止浏览器通过缓存/bfcache 回退显示过期页面
                                return ServerResponse.ok()
                                    .contentType(MediaType.TEXT_HTML)
                                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                                    .bodyValue(buildRedirectPage(
                                        finalUrl, basicSetting, styleSetting, advancedSetting));
                            });
                    });
            });
    }


    /**
     * 构建安全跳转页面 HTML
     */
    private String buildRedirectPage(String targetUrl,
                                     BasicSetting basic,
                                     StyleSetting style,
                                     AdvancedSetting advanced) {
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String displayUrl = targetUrl.length() > 80
            ? targetUrl.substring(0, 80) + "..."
            : targetUrl;
        String tipText = (advanced.getCustomTip() != null && !advanced.getCustomTip().isBlank())
            ? advanced.getCustomTip()
            : "您即将离开 <strong>" + escapeHtml(basic.getSiteName())
                + "</strong>，前往以下外部网站。外部链接的内容不受本站控制，请谨慎访问。";

        int countdown = style.getCountdown();
        // 脚本始终注入（即使倒计时为 0），用于拦截"确认跳转"并覆盖历史记录，防止回退到本页
        String pageScripts = buildPageScripts(countdown, targetUrl);

        String countdownHtmlUI = countdown > 0
            ? "<div class=\"sr-countdown mt-4\">"
                + "<div class=\"sr-countdown-icon\">⏱</div>"
                + "<span class=\"sr-countdown-text\"><span id=\"countdown-num\">" + countdown + "</span> 秒后自动跳转...</span>"
                + "</div>"
            : "";

        String qrCodeHtmlUI = "";
        if (style.isShowQrCode()) {
            qrCodeHtmlUI = "<div class=\"sr-qrcode animate-fade-in-delay-3\">"
                + "<p class=\"sr-qrcode-label\">扫码在移动端查看</p>"
                + "<img src=\"https://api.qrserver.com/v1/create-qr-code/?size=120x120&data="
                + encodedUrl + "\" alt=\"二维码\" class=\"sr-qrcode-img\"/>"
                + "</div>";
        }

        String urlDisplayHtmlUI = style.isShowTargetUrl()
            ? "<div class=\"sr-url-container animate-fade-in-delay-2\">"
                + "<p class=\"sr-url-label\">目标地址</p>"
                + "<code class=\"sr-url-text\">" + escapeHtml(displayUrl) + "</code>"
                + "</div>"
            : "";

        // 自定义 HTML 代码（不转义，直接输出）
        String customHtmlUI = (style.getCustomHtml() != null && !style.getCustomHtml().trim().isEmpty())
            ? style.getCustomHtml().trim()
            : "";

        // 获取主题样式（custom 主题使用高级设置中的自定义 CSS）
        String themeStyles = buildThemeStyles(style.getTheme(), advanced.getCustomCss());

        // 自定义背景图片（可选）：覆盖主题默认渐变背景，留空则无输出
        String bgImageCss = "";
        String backgroundImageUrl = style.getBackgroundImageUrl();
        if (backgroundImageUrl != null && !backgroundImageUrl.trim().isEmpty()) {
            bgImageCss = "    /* 自定义背景图片 */\n"
                + "    body { background-image: url('" + escapeCssUrl(backgroundImageUrl.trim()) + "'); "
                + "background-size: cover; background-position: center; background-attachment: fixed; }\n";
        }

        // 构建图标
        String iconHtml;
        String iconUrl = style.getIconUrl();
        if (iconUrl != null && !iconUrl.trim().isEmpty()) {
            // 自定义图片图标
            iconHtml = "<img src=\"" + escapeHtml(iconUrl.trim()) + "\" alt=\"图标\" class=\"sr-icon-img\"/>";
        } else {
            // 默认图标：外部链接箭头 SVG
            iconHtml = "<svg class=\"sr-icon-svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\">"
                + "<circle cx=\"12\" cy=\"12\" r=\"10\" class=\"sr-icon-ring\"/>"
                + "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\" class=\"sr-icon-path\"/>"
                + "<path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\" class=\"sr-icon-path\"/>"
                + "</svg>";
        }

        return "<!DOCTYPE html>\n"
            + "<html lang=\"zh-CN\">\n"
            + "<head>\n"
            + "  <meta charset=\"UTF-8\">\n"
            + "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
            + "  <meta name=\"robots\" content=\"noindex,nofollow\">\n"
            + "  <meta http-equiv=\"Cache-Control\" content=\"no-store\">\n"
            + "  <title>" + escapeHtml(basic.getPageTitle()) + "</title>\n"
            + "  <style>\n"
            + "    /* 二维码 */\n"
            + "    .sr-qrcode { text-align: center; margin-bottom: 24px; }\n"
            + "    .sr-qrcode-label { font-size: 12px; color: #9ca3af; margin-bottom: 8px; }\n"
            + "    .sr-qrcode-img { border: 2px solid #e5e7eb; border-radius: 8px; }\n"
            + "\n"
            + "    /* 倒计时 */\n"
            + "    .sr-countdown { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; gap: 8px; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }\n"
            + "    .sr-countdown-icon { font-size: 18px; color: #f59e0b; }\n"
            + "    .sr-countdown-text { font-size: 14px; color: #92400e; }\n"
            + "    #countdown-num { font-weight: 700; color: #f59e0b; }\n"
            + "\n"
            + "    /* 按钮 */\n"
            + "    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }\n"
            + "    .sr-btn { flex: 1; padding: 14px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; text-decoration: none; }\n"
            + "    .sr-btn-primary { background: linear-gradient(135deg, #3B82F6 0%, #2563eb 100%); color: white; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }\n"
            + "    .sr-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4); }\n"
            + "    .sr-btn-secondary { background: transparent; color: #6b7280; border: 2px solid #e5e7eb; }\n"
            + "    .sr-btn-secondary:hover { border-color: #9ca3af; color: #374151; background: #f9fafb; }\n"
            + "\n"
            + "    /* 动画 */\n"
            + "    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }\n"
            + "    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }\n"
            + "    @keyframes pulse { 0%, 100% { box-shadow: 0 10px 30px rgba(59, 130, 246, 0.4); } 50% { box-shadow: 0 10px 40px rgba(59, 130, 246, 0.6); } }\n"
            + "\n"
            + "    /* 响应式 */\n"
            + "    @media (max-width: 480px) {\n"
            + "      .sr-card { padding: 24px; }\n"
            + "      .sr-title { font-size: 20px; }\n"
            + "      .sr-buttons { flex-direction: column; }\n"
            + "    }\n"
            + "\n"
            + "    /* 主题样式最后输出：覆盖上方公共默认样式，保持所选主题的按钮等视觉风格 */\n"
            + themeStyles
            + bgImageCss
            + "  </style>\n"
            + "</head>\n"
            + "<body>\n"
            + "  <canvas id=\"particle-canvas\"></canvas>\n"
            + "  <div class=\"sr-card\">\n"
            + "    <div class=\"sr-icon-container\">" + iconHtml + "</div>\n"
            + "    <h2 class=\"sr-title\">" + escapeHtml(basic.getPageTitle()) + "</h2>\n"
            + "    <p class=\"sr-tip\">" + tipText + "</p>\n"
            + urlDisplayHtmlUI + "\n"
            + qrCodeHtmlUI + "\n"
            + countdownHtmlUI + "\n"
            + "    <div class=\"sr-buttons\">\n"
            + "      <a href=\"" + escapeHtml(targetUrl) + "\" rel=\"noopener noreferrer nofollow\" id=\"confirm-btn\" class=\"sr-btn sr-btn-primary\">"
            + "        确认跳转"
            + "      </a>"
            + "      <a href=\"javascript:history.back()\" id=\"back-btn\" class=\"sr-btn sr-btn-secondary\">"
            + "        返回上页"
            + "      </a>"
            + "    </div>"
            + customHtmlUI + "\n"
            + "  </div>"
            + pageScripts
            + "</body>"
            + "</html>";
    }

    /**
     * 构建错误页面
     */
    private String buildErrorPage(String title, String message) {
        return "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">"
            + "<title>错误 - " + escapeHtml(title) + "</title></head><body>"
            + "<h2>⚠️ " + escapeHtml(title) + "</h2>"
            + "<p>" + escapeHtml(message) + "</p>"
            + "<a href=\"javascript:history.back()\" id=\"back-btn\">返回上页</a>"
            + "<script>"
            + "var b=document.getElementById('back-btn');"
            + "if(b){b.addEventListener('click',function(e){e.preventDefault();"
            + "var f=(document.referrer&&document.referrer!==window.location.href)"
            + "?document.referrer:'/';"
            + "if(window.history.length>1){window.history.back();}else{"
            + "window.close();"
            + "setTimeout(function(){window.location.replace(f);},300);}});}"
            + "</script>"
            + "</body></html>";
    }

    /**
     * 构建页面脚本：粒子动画 + 倒计时 + 防回退跳转
     *
     * <p>所有离开本页的跳转均使用 window.location.replace()，
     * 用目标地址覆盖中间页的历史记录条目，
     * 使浏览器"后退"无法再回到本中间页，只能回到来源页面。
     */
    private String buildPageScripts(int seconds, String targetUrl) {
        // JS 字符串转义：处理反斜杠、换行、单引号及 </script> 序列，防止脚本注入
        String escaped = targetUrl
            .replace("\\", "\\\\")
            .replace("\r", "")
            .replace("\n", "")
            .replace("'", "\\'")
            .replace("</", "<\\/");
        return """
            <script>
              (function() {
                // 粒子背景动画
                var canvas = document.getElementById('particle-canvas');
                if (canvas) {
                  var ctx = canvas.getContext('2d');
                  var particles = [];
                  var mouse = { x: null, y: null };
                  
                  function resize() {
                    canvas.width = window.innerWidth;
                    canvas.height = window.innerHeight;
                  }
                  resize();
                  window.addEventListener('resize', resize);
                  
                  class Particle {
                    constructor() {
                      this.x = Math.random() * canvas.width;
                      this.y = Math.random() * canvas.height;
                      this.size = Math.random() * 2 + 1;
                      this.speedX = Math.random() * 0.8 - 0.4;
                      this.speedY = Math.random() * 0.8 - 0.4;
                      this.opacity = Math.random() * 0.5 + 0.2;
                    }
                    update() {
                      this.x += this.speedX;
                      this.y += this.speedY;
                      if (this.x < 0) this.x = canvas.width;
                      if (this.x > canvas.width) this.x = 0;
                      if (this.y < 0) this.y = canvas.height;
                      if (this.y > canvas.height) this.y = 0;
                    }
                    draw() {
                      ctx.beginPath();
                      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                      ctx.fillStyle = 'rgba(150, 150, 150, ' + this.opacity + ')';
                      ctx.fill();
                    }
                  }
                  
                  function initParticles() {
                    particles = [];
                    var count = Math.min(60, Math.floor((canvas.width * canvas.height) / 15000));
                    for (var i = 0; i < count; i++) {
                      particles.push(new Particle());
                    }
                  }
                  initParticles();
                  
                  function connectParticles() {
                    for (var i = 0; i < particles.length; i++) {
                      for (var j = i + 1; j < particles.length; j++) {
                        var dx = particles[i].x - particles[j].x;
                        var dy = particles[i].y - particles[j].y;
                        var dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 150) {
                          ctx.beginPath();
                          ctx.strokeStyle = 'rgba(150, 150, 150, ' + (0.15 - dist / 150 * 0.15) + ')';
                          ctx.lineWidth = 1;
                          ctx.moveTo(particles[i].x, particles[i].y);
                          ctx.lineTo(particles[j].x, particles[j].y);
                          ctx.stroke();
                        }
                      }
                    }
                  }
                  
                  function animate() {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    particles.forEach(function(p) { p.update(); p.draw(); });
                    connectParticles();
                    requestAnimationFrame(animate);
                  }
                  animate();
                }
                
                // 执行跳转：replace 覆盖当前历史条目，后退无法回到本页
                var timer = null;
                function jump() {
                  if (timer) {
                    clearInterval(timer);
                    timer = null;
                  }
                  window.location.replace('%s');
                }

                var el = document.getElementById('countdown-num');
                var btn = document.getElementById('confirm-btn');
                var remaining = %d;

                // 倒计时逻辑
                if (remaining > 0 && el) {
                  timer = setInterval(function() {
                    remaining--;
                    el.textContent = remaining;
                    if (remaining <= 0) {
                      clearInterval(timer);
                      jump();
                    }
                  }, 1000);
                }

                // 点击"确认跳转"：阻止默认整页导航，改用 replace 跳转
                if (btn) {
                  btn.addEventListener('click', function(e) {
                    // 保留 Ctrl/Cmd/Shift 点击在新标签页打开的能力
                    if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
                    e.preventDefault();
                    jump();
                  });
                }

                // 点击"返回上页"：优先回退浏览器历史；
                // 若中间页在新标签页打开（历史栈只有本页，history.back() 无效），
                // 则直接关闭当前标签页，浏览器会自动回到来源标签页；
                // 关闭被浏览器安全策略拒绝时，降级跳转到来源页（无来源则回首页）
                function goBack() {
                  var fallback = (document.referrer && document.referrer !== window.location.href)
                    ? document.referrer : '/';
                  if (window.history.length > 1) {
                    var left = false;
                    // pagehide 触发说明后退导航已生效；否则 500ms 后走兜底返回
                    window.addEventListener('pagehide', function() { left = true; }, { once: true });
                    window.history.back();
                    setTimeout(function() {
                      if (!left) window.location.replace(fallback);
                    }, 500);
                  } else {
                    // 作为新标签页首个页面被打开时，window.close() 可被浏览器允许执行
                    window.close();
                    // 若关闭请求被拒绝，本页面仍存活，定时器会执行并降级跳回来源页
                    setTimeout(function() {
                      window.location.replace(fallback);
                    }, 300);
                  }
                }
                var backBtn = document.getElementById('back-btn');
                if (backBtn) {
                  backBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    goBack();
                  });
                }

                // 从 bfcache/前进恢复页面时直接跳转，避免滞留在已跳转过的中间页
                window.addEventListener('pageshow', function(e) {
                  if (e.persisted) jump();
                });
              })();
            </script>
            """.formatted(escaped, seconds);
    }

    /**
     * HTML 转义，防止 XSS
     */
    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }

    /**
     * CSS url() 字符串转义：防止引号与 &lt;/style&gt; 序列提前闭合
     * <p>CSS 中反斜杠可转义任意字符，\/ 会还原为 /，但不会提前闭合 HTML 的 style 标签
     */
    private String escapeCssUrl(String input) {
        return input.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace(")", "\\)")
            .replace(";", "\\;")
            .replace("</", "<\\/");
    }

    /**
     * 构建自定义页面（用户提供的完整 HTML）
     */
    private String buildCustomPage(String targetUrl, BasicSetting basic, String customHtml) {
        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        // 支持变量替换：{url} = 目标URL，{sitename} = 网站名称
        String processedHtml = customHtml
            .replace("{url}", targetUrl)
            .replace("{sitename}", basic.getSiteName())
            .replace("{encodedurl}", encodedUrl);
        
        return "<!DOCTYPE html>\n"
            + "<html lang=\"zh-CN\">\n"
            + "<head>\n"
            + "  <meta charset=\"UTF-8\">\n"
            + "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
            + "  <meta http-equiv=\"Cache-Control\" content=\"no-store\">\n"
            + "  <title>" + escapeHtml(basic.getPageTitle()) + "</title>\n"
            + "  <style>\n"
            + "    body { margin: 0; padding: 0; }\n"
            + "  </style>\n"
            + "</head>\n"
            + "<body>\n"
            + processedHtml + "\n"
            + "</body>\n"
            + "</html>";
    }

    /**
     * 构建主题样式
     *
     * @param theme 主题标识
     * @param customCss 管理员在高级设置中填写的自定义 CSS（仅 theme=custom 时使用）
     */
    private String buildThemeStyles(String theme, String customCss) {
        if (theme == null) theme = "default";
        
        switch (theme) {
            case "minimal":
                return """
                    /* 极简主题 */
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #ffffff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
                    canvas { display: none; }
                    .sr-card { background: #ffffff; border: 2px solid #e5e7eb; border-radius: 8px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05); max-width: 480px; width: 100%; padding: 40px; animation: fadeInUp 0.6s ease-out; }
                    .sr-icon-container { width: 80px; height: 80px; margin: 0 auto 24px; display: flex; align-items: center; justify-content: center; background: #f3f4f6; border-radius: 50%; }
                    .sr-icon-svg { width: 40px; height: 40px; color: #6b7280; }
                    .sr-icon-img { width: 48px; height: 48px; object-fit: contain; border-radius: 50%; }
                    .sr-title { font-size: 22px; font-weight: 600; color: #1f2937; text-align: center; margin-bottom: 12px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip { font-size: 14px; color: #6b7280; text-align: center; line-height: 1.6; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip strong { color: #1f2937; font-weight: 600; }
                    .sr-url-container { background: #f9fafb; border-radius: 6px; padding: 16px; margin-bottom: 24px; border: 1px solid #e5e7eb; }
                    .sr-url-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
                    .sr-url-text { font-size: 12px; color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; word-break: break-all; display: block; }
                    .sr-qrcode { text-align: center; margin-bottom: 24px; }
                    .sr-qrcode-label { font-size: 12px; color: #9ca3af; margin-bottom: 8px; }
                    .sr-qrcode-img { border: 1px solid #e5e7eb; border-radius: 6px; }
                    .sr-countdown { background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px 16px; display: flex; align-items: center; gap: 8px; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-countdown-icon { font-size: 16px; color: #1f2937; }
                    .sr-countdown-text { font-size: 14px; color: #4b5563; }
                    #countdown-num { font-weight: 600; color: #1f2937; }
                    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-btn { flex: 1; padding: 12px 20px; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; text-decoration: none; }
                    .sr-btn-primary { background: #1f2937; color: white; }
                    .sr-btn-primary:hover { background: #374151; }
                    .sr-btn-secondary { background: #ffffff; color: #6b7280; border: 2px solid #e5e7eb; }
                    .sr-btn-secondary:hover { border-color: #9ca3af; color: #374151; background: #f9fafb; }
                    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
                    @media (max-width: 480px) {
                      .sr-card { padding: 24px; }
                      .sr-title { font-size: 18px; }
                      .sr-buttons { flex-direction: column; }
                    }
                    """;
                
            case "tech":
                return """
                    /* 科技主题 */
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: 'Courier New', monospace; background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
                    canvas { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; }
                    .sr-card { background: rgba(26, 26, 46, 0.9); border: 1px solid #00f0ff; border-radius: 4px; box-shadow: 0 0 30px rgba(0, 240, 255, 0.2); max-width: 480px; width: 100%; padding: 40px; animation: fadeInUp 0.6s ease-out; backdrop-filter: blur(10px); }
                    .sr-icon-container { width: 80px; height: 80px; margin: 0 auto 24px; animation: float 3s ease-in-out infinite; display: flex; align-items: center; justify-content: center; background: rgba(0, 240, 255, 0.1); border: 2px solid #00f0ff; border-radius: 4px; box-shadow: 0 0 20px rgba(0, 240, 255, 0.3); }
                    .sr-icon-svg { width: 40px; height: 40px; color: #00f0ff; }
                    .sr-icon-img { width: 48px; height: 48px; object-fit: contain; }
                    .sr-title { font-size: 20px; font-weight: 700; color: #00f0ff; text-align: center; margin-bottom: 12px; animation: fadeInUp 0.6s ease-out 0.1s both; text-transform: uppercase; letter-spacing: 2px; }
                    .sr-tip { font-size: 13px; color: #a0aec0; text-align: center; line-height: 1.6; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip strong { color: #00f0ff; }
                    .sr-url-container { background: rgba(0, 240, 255, 0.05); border: 1px solid #00f0ff; border-radius: 4px; padding: 16px; margin-bottom: 24px; }
                    .sr-url-label { font-size: 10px; color: #00f0ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
                    .sr-url-text { font-size: 11px; color: #00f0ff; font-family: 'Courier New', monospace; word-break: break-all; display: block; }
                    .sr-qrcode { text-align: center; margin-bottom: 24px; }
                    .sr-qrcode-label { font-size: 11px; color: #00f0ff; margin-bottom: 8px; }
                    .sr-qrcode-img { border: 1px solid #00f0ff; border-radius: 4px; }
                    .sr-countdown { background: rgba(0, 240, 255, 0.1); border: 1px solid #00f0ff; border-radius: 4px; padding: 12px 16px; display: flex; align-items: center; gap: 8px; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-countdown-icon { font-size: 16px; color: #00f0ff; }
                    .sr-countdown-text { font-size: 13px; color: #00f0ff; }
                    #countdown-num { font-weight: 700; color: #00f0ff; }
                    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-btn { flex: 1; padding: 14px 24px; border: 2px solid #00f0ff; border-radius: 4px; font-size: 14px; font-weight: 700; cursor: pointer; transition: all 0.3s ease; text-decoration: none; text-transform: uppercase; letter-spacing: 1px; }
                    .sr-btn-primary { background: #00f0ff; color: #0f0f23; }
                    .sr-btn-primary:hover { background: #00c8d4; box-shadow: 0 0 20px rgba(0, 240, 255, 0.4); }
                    .sr-btn-secondary { background: transparent; color: #00f0ff; }
                    .sr-btn-secondary:hover { background: rgba(0, 240, 255, 0.1); color: #00f0ff; }
                    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
                    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }
                    @media (max-width: 480px) {
                      .sr-card { padding: 24px; }
                      .sr-title { font-size: 16px; }
                      .sr-buttons { flex-direction: column; }
                    }
                    """;
                
            case "warm":
                return """
                    /* 温暖主题 */
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
                    canvas { display: none; }
                    .sr-card { background: rgba(255, 255, 255, 0.9); border-radius: 20px; box-shadow: 0 10px 40px rgba(251, 146, 60, 0.3); max-width: 480px; width: 100%; padding: 40px; animation: fadeInUp 0.6s ease-out; backdrop-filter: blur(10px); }
                    .sr-icon-container { width: 80px; height: 80px; margin: 0 auto 24px; animation: float 3s ease-in-out infinite; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, #f97316 0%, #fbbf24 100%); border-radius: 20px; box-shadow: 0 8px 20px rgba(249, 115, 22, 0.4); }
                    .sr-icon-svg { width: 40px; height: 40px; color: white; }
                    .sr-icon-img { width: 48px; height: 48px; object-fit: contain; border-radius: 12px; }
                    .sr-title { font-size: 24px; font-weight: 700; color: #1f2937; text-align: center; margin-bottom: 12px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip { font-size: 14px; color: #6b7280; text-align: center; line-height: 1.6; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip strong { color: #f97316; }
                    .sr-url-container { background: #fff7ed; border-radius: 12px; padding: 16px; margin-bottom: 24px; border: 1px solid #fed7aa; }
                    .sr-url-label { font-size: 11px; color: #fb923c; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
                    .sr-url-text { font-size: 12px; color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; word-break: break-all; display: block; }
                    .sr-qrcode { text-align: center; margin-bottom: 24px; }
                    .sr-qrcode-label { font-size: 12px; color: #fb923c; margin-bottom: 8px; }
                    .sr-qrcode-img { border: 2px solid #fed7aa; border-radius: 12px; }
                    .sr-countdown { background: #fff7ed; border: 1px solid #f97316; border-radius: 12px; padding: 12px 16px; display: flex; align-items: center; gap: 8px; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-countdown-icon { font-size: 18px; color: #f97316; }
                    .sr-countdown-text { font-size: 14px; color: #9a3412; }
                    #countdown-num { font-weight: 700; color: #f97316; }
                    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-btn { flex: 1; padding: 14px 24px; border: none; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; text-decoration: none; }
                    .sr-btn-primary { background: linear-gradient(135deg, #f97316 0%, #fbbf24 100%); color: white; box-shadow: 0 4px 12px rgba(249, 115, 22, 0.3); }
                    .sr-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(249, 115, 22, 0.4); }
                    .sr-btn-secondary { background: #ffffff; color: #6b7280; border: 2px solid #fed7aa; }
                    .sr-btn-secondary:hover { border-color: #f97316; color: #f97316; background: #fff7ed; }
                    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
                    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }
                    @media (max-width: 480px) {
                      .sr-card { padding: 24px; }
                      .sr-title { font-size: 20px; }
                      .sr-buttons { flex-direction: column; }
                    }
                    """;
                
            case "custom":
                // 使用管理员自定义 CSS；为空则回退到默认主题
                if (customCss != null && !customCss.trim().isEmpty()) {
                    return customCss.replace("</style", "<\\/style")
                        .replace("</", "<\\/");
                }
                return """
                    /* 默认主题（未提供自定义 CSS） */
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
                    canvas { display: none; }
                    .sr-card { background: #ffffff; border-radius: 12px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1); max-width: 480px; width: 100%; padding: 40px; }
                    .sr-title { font-size: 22px; font-weight: 600; color: #1f2937; text-align: center; margin-bottom: 12px; }
                    .sr-tip { font-size: 14px; color: #6b7280; text-align: center; line-height: 1.6; margin-bottom: 24px; }
                    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; }
                    .sr-btn { flex: 1; padding: 14px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; }
                    .sr-btn-primary { background: #3B82F6; color: white; }
                    .sr-btn-secondary { background: transparent; color: #6b7280; border: 2px solid #e5e7eb; }
                    """;
                
            default: // default theme
                return """
                    /* 默认主题 */
                    * { box-sizing: border-box; margin: 0; padding: 0; }
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
                    canvas { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; }
                    .sr-card { background: rgba(255, 255, 255, 0.95); border-radius: 16px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); max-width: 480px; width: 100%; padding: 40px; animation: fadeInUp 0.6s ease-out; backdrop-filter: blur(20px); }
                    .sr-icon-container { width: 80px; height: 80px; margin: 0 auto 24px; animation: float 3s ease-in-out infinite; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 100%); border-radius: 16px; box-shadow: 0 10px 30px rgba(59, 130, 246, 0.4); }
                    .sr-icon-svg { width: 40px; height: 40px; color: white; }
                    .sr-icon-ring { opacity: 0.3; }
                    .sr-icon-path { opacity: 0.9; }
                    .sr-icon-img { width: 48px; height: 48px; object-fit: contain; border-radius: 8px; }
                    .sr-title { font-size: 24px; font-weight: 700; color: #1f2937; text-align: center; margin-bottom: 12px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip { font-size: 14px; color: #6b7280; text-align: center; line-height: 1.6; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.1s both; }
                    .sr-tip strong { color: #3B82F6; }
                    .sr-url-container { background: #f3f4f6; border-radius: 8px; padding: 16px; margin-bottom: 24px; }
                    .sr-url-label { font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
                    .sr-url-text { font-size: 12px; color: #4b5563; font-family: 'Monaco', 'Courier New', monospace; word-break: break-all; display: block; }
                    .sr-qrcode { text-align: center; margin-bottom: 24px; }
                    .sr-qrcode-label { font-size: 12px; color: #9ca3af; margin-bottom: 8px; }
                    .sr-qrcode-img { border: 2px solid #e5e7eb; border-radius: 8px; }
                    .sr-countdown { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; gap: 8px; margin-bottom: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-countdown-icon { font-size: 18px; color: #f59e0b; }
                    .sr-countdown-text { font-size: 14px; color: #92400e; }
                    #countdown-num { font-weight: 700; color: #f59e0b; }
                    .sr-buttons { display: flex; gap: 12px; margin-top: 24px; animation: fadeInUp 0.6s ease-out 0.3s both; }
                    .sr-btn { flex: 1; padding: 14px 24px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; text-decoration: none; }
                    .sr-btn-primary { background: linear-gradient(135deg, #3B82F6 0%, #2563eb 100%); color: white; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
                    .sr-btn-primary:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4); }
                    .sr-btn-secondary { background: transparent; color: #6b7280; border: 2px solid #e5e7eb; }
                    .sr-btn-secondary:hover { border-color: #9ca3af; color: #374151; background: #f9fafb; }
                    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
                    @keyframes float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }
                    @keyframes pulse { 0%, 100% { box-shadow: 0 10px 30px rgba(59, 130, 246, 0.4); } 50% { box-shadow: 0 10px 40px rgba(59, 130, 246, 0.6); } }
                    @media (max-width: 480px) {
                      .sr-card { padding: 24px; }
                      .sr-title { font-size: 20px; }
                      .sr-buttons { flex-direction: column; }
                    }
                    """;
        }
    }
}



