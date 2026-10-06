package run.halo.saferedirect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@link WhitelistMatcher} 单元测试
 */
class WhitelistMatcherTest {

    // ---------- matchesHost ----------

    @Test
    @DisplayName("普通域名：主域精确匹配")
    void matchesHostExact() {
        assertTrue(WhitelistMatcher.matchesHost("example.com", "example.com"));
    }

    @Test
    @DisplayName("普通域名：子域命中（后缀匹配）")
    void matchesHostSubdomain() {
        assertTrue(WhitelistMatcher.matchesHost("blog.example.com", "example.com"));
    }

    @Test
    @DisplayName("普通域名：不相关域不匹配")
    void matchesHostDifferent() {
        assertFalse(WhitelistMatcher.matchesHost("evil.com", "example.com"));
    }

    @Test
    @DisplayName("普通域名：避免前缀误匹配（example.com 不应命中 notexample.com）")
    void matchesHostNoPartialPrefixMatch() {
        assertFalse(WhitelistMatcher.matchesHost("notexample.com", "example.com"));
    }

    @Test
    @DisplayName("泛域名 *.example.com：匹配主域")
    void matchesWildcardMainDomain() {
        assertTrue(WhitelistMatcher.matchesHost("example.com", "*.example.com"));
    }

    @Test
    @DisplayName("泛域名 *.example.com：匹配多级子域")
    void matchesWildcardDeepSubdomain() {
        assertTrue(WhitelistMatcher.matchesHost("a.b.example.com", "*.example.com"));
    }

    @Test
    @DisplayName("泛域名 *.example.com：不匹配不相关域")
    void matchesWildcardDifferent() {
        assertFalse(WhitelistMatcher.matchesHost("other.com", "*.example.com"));
    }

    @Test
    @DisplayName("大小写不敏感")
    void matchesHostIgnoreCase() {
        assertTrue(WhitelistMatcher.matchesHost("BLOG.Example.COM", "EXAMPLE.com"));
        assertTrue(WhitelistMatcher.matchesHost("EXAMPLE.com", "*.example.com"));
    }

    @Test
    @DisplayName("空 host 或空规则返回 false")
    void matchesHostBlank() {
        assertFalse(WhitelistMatcher.matchesHost("", "example.com"));
        assertFalse(WhitelistMatcher.matchesHost(null, "example.com"));
        assertFalse(WhitelistMatcher.matchesHost("example.com", ""));
        assertFalse(WhitelistMatcher.matchesHost("example.com", null));
    }

    // ---------- isWhitelisted ----------

    @Test
    @DisplayName("URL 命中白名单返回 true")
    void isWhitelistedHit() {
        assertTrue(WhitelistMatcher.isWhitelisted("https://github.com/x", "github.com\ngoogle.com"));
    }

    @Test
    @DisplayName("URL 命中泛域名白名单返回 true")
    void isWhitelistedWildcardHit() {
        assertTrue(WhitelistMatcher.isWhitelisted("https://blog.github.com/x", "*.github.com"));
    }

    @Test
    @DisplayName("URL 不在白名单返回 false")
    void isWhitelistedMiss() {
        assertFalse(WhitelistMatcher.isWhitelisted("https://evil.com/x", "github.com"));
    }

    @Test
    @DisplayName("支持逗号分隔白名单")
    void isWhitelistedCommaSeparated() {
        assertTrue(WhitelistMatcher.isWhitelisted("https://a.com/x", "github.com,a.com"));
    }

    @Test
    @DisplayName("空输入返回 false")
    void isWhitelistedBlank() {
        assertFalse(WhitelistMatcher.isWhitelisted("", "github.com"));
        assertFalse(WhitelistMatcher.isWhitelisted(null, "github.com"));
        assertFalse(WhitelistMatcher.isWhitelisted("https://github.com/x", ""));
        assertFalse(WhitelistMatcher.isWhitelisted("https://github.com/x", null));
        assertFalse(WhitelistMatcher.isWhitelisted("https://github.com/x", "\n\n"));
    }

    @Test
    @DisplayName("无 host 的 URL 返回 false")
    void isWhitelistedNoHost() {
        assertFalse(WhitelistMatcher.isWhitelisted("javascript:alert(1)", "github.com"));
        assertFalse(WhitelistMatcher.isWhitelisted("mailto:user@example.com", "example.com"));
    }

    // ---------- buildWhitelistJs ----------

    @Test
    @DisplayName("空白名单生成空数组")
    void buildWhitelistJsBlank() {
        assertEquals("[]", WhitelistMatcher.buildWhitelistJs(null));
        assertEquals("[]", WhitelistMatcher.buildWhitelistJs(""));
        assertEquals("[]", WhitelistMatcher.buildWhitelistJs("   \n  "));
    }

    @Test
    @DisplayName("普通域名与泛域名转 JS 数组")
    void buildWhitelistJsNormal() {
        assertEquals(
            "[\"github.com\",\"*.example.com\"]",
            WhitelistMatcher.buildWhitelistJs("github.com\n*.example.com"));
    }

    @Test
    @DisplayName("过滤空项并统一小写")
    void buildWhitelistJsFiltersBlanks() {
        assertEquals(
            "[\"github.com\",\"example.com\"]",
            WhitelistMatcher.buildWhitelistJs("GITHUB.COM\n\n  example.com  "));
    }

    @Test
    @DisplayName("非法字符被净化，防止注入")
    void buildWhitelistJsSanitizes() {
        String result = WhitelistMatcher.buildWhitelistJs("safe.example.com\"><script>alert(1)</script>");
        // 净化只保留合法字符：<、>、" 等非法字符被移除
        assertFalse(result.contains("<"));
        assertFalse(result.contains(">"));
        assertFalse(result.contains("\""));
        assertFalse(result.contains("</script>"));
        assertTrue(result.startsWith("[\""));
    }

    @Test
    @DisplayName("仅含非法字符的输入被清空后不产生有效条目")
    void buildWhitelistJsAllIllegal() {
        assertEquals("[]", WhitelistMatcher.buildWhitelistJs("><script"));
    }
}
