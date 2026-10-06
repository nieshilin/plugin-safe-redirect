package run.halo.saferedirect;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.model.IModel;
import org.thymeleaf.model.IModelFactory;
import org.thymeleaf.processor.element.IElementModelStructureHandler;
import reactor.core.publisher.Mono;
import run.halo.app.plugin.ReactiveSettingFetcher;
import run.halo.app.theme.dialect.TemplateHeadProcessor;

/**
 * 主题端 HEAD 注入处理器
 *
 * <p>在主题的每个页面 &lt;head&gt; 末尾注入一段轻量 JavaScript：
 * <ul>
 *   <li>自动拦截页面内所有外部链接（不在白名单内）的点击事件</li>
 *   <li>将外链重写为 /plugins/plugin-safe-redirect/go?url=... 形式</li>
 *   <li>站内链接（同域名）不受影响</li>
 *   <li>带有 data-no-redirect 属性的链接跳过拦截</li>
 * </ul>
 *
 * @author SafeRedirect Team
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SafeRedirectHeadProcessor implements TemplateHeadProcessor {

    private final ReactiveSettingFetcher settingFetcher;

    @Override
    public Mono<Void> process(ITemplateContext context,
                              IModel model,
                              IElementModelStructureHandler handler) {
        return settingFetcher.fetch("basic", BasicSetting.class)
            .defaultIfEmpty(new BasicSetting())
            .doOnNext(basic -> {
                if (!basic.isEnabled()) {
                    // 插件禁用时不注入任何代码
                    log.debug("SafeRedirect plugin is disabled, skipping head injection.");
                    return;
                }
                // 构建白名单数组 JS 代码
                String whitelistJs = buildWhitelistJs(basic.getWhitelistDomains());
                String script = buildInjectedScript(whitelistJs);

                // 向 <head> 追加 script 标签
                IModelFactory modelFactory = context.getConfiguration().getModelFactory(
                    context.getTemplateMode());
                IModel scriptModel = modelFactory.createModel();
                scriptModel.add(modelFactory.createText(script));
                model.addModel(scriptModel);

                log.debug("SafeRedirect: injected link-intercept script into <head>.");
            })
            .then();
    }

    /**
     * 将白名单字符串转换为 JS 数组字面量
     * <p>例如："github.com\n*.example.com" → '["github.com","*.example.com"]'
     * <p>支持 *.example.com 泛域名写法，匹配 example.com 及其所有子域名
     */
    private String buildWhitelistJs(String whitelistDomains) {
        if (whitelistDomains == null || whitelistDomains.isBlank()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        String[] domains = whitelistDomains.split("[\n,]");
        boolean first = true;
        for (String domain : domains) {
            String trimmed = domain.trim().toLowerCase();
            if (!trimmed.isBlank()) {
                if (!first) sb.append(",");
                // 对域名做基础净化，只保留合法字符，防止注入；泛域名保留 "*." 前缀
                String safe;
                if (trimmed.startsWith("*.")) {
                    safe = "*." + trimmed.substring(2).replaceAll("[^a-zA-Z0-9.\\-]", "");
                } else {
                    safe = trimmed.replaceAll("[^a-zA-Z0-9.\\-]", "");
                }
                sb.append("\"").append(safe).append("\"");
                first = false;
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * 构建注入到 &lt;head&gt; 的完整 script 标签
     */
    private String buildInjectedScript(String whitelistJs) {
        return """
            <script data-plugin="safe-redirect">
            (function() {
              'use strict';
              // 安全链接跳转插件 - 链接拦截脚本
              var REDIRECT_BASE = '/plugins/plugin-safe-redirect/go';
              var WHITELIST = %s;
              var currentHost = window.location.hostname;

              function isDomainWhitelisted(hostname) {
                return WHITELIST.some(function(entry) {
                  // 支持泛域名写法 *.example.com：剥去 "*." 前缀后匹配主域及其所有子域名
                  var base = entry.indexOf('*.') === 0 ? entry.substring(2) : entry;
                  return hostname === base || hostname.endsWith('.' + base);
                });
              }

              function isExternalLink(href) {
                try {
                  var url = new URL(href, window.location.href);
                  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
                  if (url.hostname === currentHost) return false;
                  if (isDomainWhitelisted(url.hostname)) return false;
                  return true;
                } catch (e) {
                  return false;
                }
              }

              function rewriteLink(anchor) {
                if (anchor.hasAttribute('data-no-redirect')) return;
                if (anchor.hasAttribute('data-sr-processed')) return;
                var href = anchor.getAttribute('href');
                if (!href || !isExternalLink(href)) return;
                anchor.setAttribute('data-sr-processed', '1');
                anchor.setAttribute('data-sr-original', href);
                anchor.href = REDIRECT_BASE + '?url=' + encodeURIComponent(href);
              }

              function processAllLinks() {
                document.querySelectorAll('a[href]').forEach(rewriteLink);
              }

              if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', processAllLinks);
              } else {
                processAllLinks();
              }

              var observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                  mutation.addedNodes.forEach(function(node) {
                    if (node.nodeType === 1) {
                      if (node.tagName === 'A') {
                        rewriteLink(node);
                      } else if (node.querySelectorAll) {
                        node.querySelectorAll('a[href]').forEach(rewriteLink);
                      }
                    }
                  });
                });
              });
              observer.observe(document.body || document.documentElement, {
                childList: true, subtree: true
              });
            })();
            </script>
            """.formatted(whitelistJs);
    }
}
