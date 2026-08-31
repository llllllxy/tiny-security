package org.tinycloud.security.util.idgen;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NanoId 凭证 ID 生成器测试。
 *
 * <p>NanoId 作为框架保留的三种安全凭证风格之一，需验证其长度、字符集与随机性。
 */
class NanoIdTest {

    private static final char[] DEFAULT_ALPHABET =
            "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

    @Test
    void shouldGenerateDefaultLength() {
        String id = NanoId.INSTANCE.randomNanoId();

        assertEquals(21, id.length());
    }

    @Test
    void shouldUseUrlSafeAlphabet() {
        String id = NanoId.INSTANCE.randomNanoId();

        for (char c : id.toCharArray()) {
            assertTrue(containsChar(DEFAULT_ALPHABET, c), "unexpected char: " + c);
        }
    }

    @Test
    void shouldGenerateDifferentIds() {
        String id1 = NanoId.INSTANCE.randomNanoId();
        String id2 = NanoId.INSTANCE.randomNanoId();

        assertNotEquals(id1, id2);
    }

    @Test
    void shouldSupportCustomSize() {
        assertEquals(16, NanoId.INSTANCE.randomNanoId(16).length());
        assertEquals(32, NanoId.INSTANCE.randomNanoId(32).length());
    }

    @Test
    void shouldHaveLowCollisionRateInBatch() {
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            assertTrue(ids.add(NanoId.INSTANCE.randomNanoId()), "collision at iteration " + i);
        }
    }

    private boolean containsChar(char[] chars, char target) {
        for (char c : chars) {
            if (c == target) {
                return true;
            }
        }
        return false;
    }
}
