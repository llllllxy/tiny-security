package org.tinycloud.security.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * TokenSignUtil 测试。
 *
 * <p>取代原 JwtUtilTest：token 的「签名」从 JWT 换成了紧凑的 HMAC 串，需要重新锁定语义——
 * ① 同一密钥能正确验签并取回凭证；② 换密钥 / 篡改凭证 / 篡改签名 / 格式非法一律失败；
 * ③ 空密钥必须显式报错，不能静默放过。</p>
 *
 * @author liuxingyu01
 */
class TokenSignUtilTest {

    private static final String SECRET = "test-secret-key-0123456789abcdef";

    /**
     * 签名 → 验签 的往返：token 形如 credentials.signature。
     */
    @Test
    void shouldSignAndVerify() {
        String token = TokenSignUtil.sign(SECRET, "cred-1");

        assertTrue(token.startsWith("cred-1."));
        assertEquals("cred-1", TokenSignUtil.verifyAndExtract(SECRET, token));
    }

    /**
     * 换一个密钥就必须验签失败（这正是「防伪造」的来源：攻击者不知道密钥就构造不出合法 token）。
     */
    @Test
    void shouldRejectWhenSecretDiffers() {
        String token = TokenSignUtil.sign(SECRET, "cred-1");

        assertNull(TokenSignUtil.verifyAndExtract("another-secret", token));
    }

    /**
     * 篡改凭证部分：签名对不上，必须拒绝。
     */
    @Test
    void shouldRejectTamperedCredentials() {
        String token = TokenSignUtil.sign(SECRET, "cred-1");
        String tampered = "cred-2" + token.substring("cred-1".length());

        assertNull(TokenSignUtil.verifyAndExtract(SECRET, tampered));
    }

    /**
     * 篡改签名部分：追加字符、或拿另一个凭证的签名冒名顶替，都必须拒绝。
     */
    @Test
    void shouldRejectTamperedSignature() {
        String token = TokenSignUtil.sign(SECRET, "cred-1");
        // 签名变长，必然对不上
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, token + "x"));

        // 把 cred-2 的签名拼到 cred-1 上冒名顶替
        String otherSignature = TokenSignUtil.sign(SECRET, "cred-2").substring("cred-2.".length());
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, "cred-1." + otherSignature));
    }

    /**
     * 格式非法（空值 / 无分隔符 / 分隔符在首尾 / 签名不是 base64url）一律返回 null，不得抛异常穿透到调用方。
     */
    @Test
    void shouldRejectMalformedToken() {
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, null));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, ""));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, "   "));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, "no-separator"));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, ".only-signature"));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, "only-credentials."));
        assertNull(TokenSignUtil.verifyAndExtract(SECRET, "cred-1.!!!not-base64url!!!"));
    }

    /**
     * 空密钥属于配置错误（不是普通验签失败），必须显式抛异常，不能静默放过。
     */
    @Test
    void shouldRejectEmptySecret() {
        String token = TokenSignUtil.sign(SECRET, "cred-1");

        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.sign(null, "cred-1"));
        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.sign("", "cred-1"));
        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.verifyAndExtract(null, token));
        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.verifyAndExtract("  ", token));
    }

    /**
     * 空凭证不允许签名。
     */
    @Test
    void shouldRejectEmptyCredentials() {
        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.sign(SECRET, null));
        assertThrows(IllegalArgumentException.class, () -> TokenSignUtil.sign(SECRET, ""));
    }

    /**
     * 不同凭证得到不同签名（否则签名就失去区分能力了）。
     */
    @Test
    void shouldProduceDifferentSignatureForDifferentCredentials() {
        assertNotEquals(TokenSignUtil.sign(SECRET, "cred-1"), TokenSignUtil.sign(SECRET, "cred-2"));
    }
}
