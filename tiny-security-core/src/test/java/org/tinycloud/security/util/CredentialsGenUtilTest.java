package org.tinycloud.security.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭证生成器测试。
 *
 * <p>核心回归点（1.3.3）：snowflake/objectid/ulid 三种含时间戳、可被预测的凭证风格已被移除，
 * 仅保留 uuid/random128/nanoid 三种具备密码学随机性的风格；null 或未知/非法风格一律回退 uuid。</p>
 */
class CredentialsGenUtilTest {

    @Test
    void shouldGenerateUuidStyleCredentials() {
        String token = CredentialsGenUtil.generate("uuid");

        assertNotNull(token);
        // UUID v4 去掉连字符后为 32 位十六进制
        assertEquals(32, token.length());
        assertTrue(token.matches("[0-9a-f]{32}"));
    }

    @Test
    void shouldGenerateRandom128StyleCredentials() {
        String token = CredentialsGenUtil.generate("random128");

        assertNotNull(token);
        assertEquals(128, token.length());
        assertTrue(token.matches("[a-zA-Z0-9_]{128}"));
    }

    @Test
    void shouldGenerateNanoidStyleCredentials() {
        String token = CredentialsGenUtil.generate("nanoid");

        assertNotNull(token);
        // NanoId 默认 21 字符
        assertEquals(21, token.length());
    }

    @Test
    void shouldFallbackToUuidWhenStyleIsNull() {
        String token = CredentialsGenUtil.generate(null);

        assertNotNull(token);
        assertEquals(32, token.length());
    }

    @Test
    void shouldFallbackToUuidWhenStyleIsEmpty() {
        String token = CredentialsGenUtil.generate("");

        assertEquals(32, token.length());
    }

    /**
     * 已移除的可预测风格（snowflake/objectid/ulid）必须回退为 uuid，不得再生成可预测凭证。
     */
    @Test
    void shouldFallbackToUuidForRemovedPredictableStyles() {
        for (String style : new String[]{"snowflake", "objectid", "ulid"}) {
            String token = CredentialsGenUtil.generate(style);
            assertEquals(32, token.length(), "style [" + style + "] must fallback to uuid");
            assertTrue(token.matches("[0-9a-f]{32}"), "style [" + style + "] must be uuid-like, but got: " + token);
        }
    }

    @Test
    void shouldFallbackToUuidForUnknownStyle() {
        String token = CredentialsGenUtil.generate("unknown-style");

        assertEquals(32, token.length());
    }

    @Test
    void shouldGenerateDifferentTokensEachCall() {
        String token1 = CredentialsGenUtil.generate("uuid");
        String token2 = CredentialsGenUtil.generate("uuid");

        assertFalse(token1.equals(token2));
    }
}
