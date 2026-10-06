package run.halo.saferedirect;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * 白名单域名匹配工具类（纯静态、无外部依赖，便于单元测试）
 *
 * <p>支持泛域名写法 {@code *.example.com}：剥去 "{@code *.}" 前缀后，匹配主域及其所有子域名。
 */
public final class WhitelistMatcher {

    private WhitelistMatcher() {
    }

    /**
     * 判断单个 host 是否匹配单个白名单域名规则（忽略大小写）。
     *
     * @param host       待匹配的主机名（如 {@code sub.example.com}）
     * @param domainRule 白名单规则（如 {@code example.com} 或 {@code *.example.com}）
     */
    public static boolean matchesHost(String host, String domainRule) {
        if (host == null || host.isBlank() || domainRule == null || domainRule.isBlank()) {
            return false;
        }
        String lowerHost = host.toLowerCase();
        String lowerDomain = domainRule.toLowerCase();
        String baseDomain = lowerDomain.startsWith("*.")
            ? lowerDomain.substring(2)
            : lowerDomain;
        return lowerHost.equals(baseDomain) || lowerHost.endsWith("." + baseDomain);
    }

    /**
     * 检查目标 URL 的 host 是否命中白名单。
     *
     * <p>白名单按换行符或逗号分隔，支持泛域名 {@code *.example.com}。
     * URL 解析失败或没有 host（如 {@code javascript:}）时返回 false。
     */
    public static boolean isWhitelisted(String targetUrl, String whitelistDomains) {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            return false;
        }
        if (whitelistDomains == null || whitelistDomains.trim().isEmpty()) {
            return false;
        }
        List<String> domains = Arrays.stream(whitelistDomains.split("[\n,]"))
            .map(String::trim)
            .filter(d -> !d.isEmpty())
            .toList();
        if (domains.isEmpty()) {
            return false;
        }
        try {
            URI uri = URI.create(targetUrl);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            return domains.stream().anyMatch(domain -> matchesHost(host, domain));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 将白名单字符串转换为 JS 数组字面量，供前端注入脚本使用。
     *
     * <p>例如 {@code "github.com\n*.example.com"} → {@code ["github.com","*.example.com"]}。
     * 会过滤空项、转小写并做基础净化，仅保留合法字符，防止注入。
     */
    public static String buildWhitelistJs(String whitelistDomains) {
        if (whitelistDomains == null || whitelistDomains.isBlank()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        String[] domains = whitelistDomains.split("[\n,]");
        boolean first = true;
        for (String domain : domains) {
            String trimmed = domain.trim().toLowerCase();
            if (!trimmed.isBlank()) {
                if (!first) {
                    sb.append(",");
                }
                // 泛域名保留 "*." 前缀
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
}
