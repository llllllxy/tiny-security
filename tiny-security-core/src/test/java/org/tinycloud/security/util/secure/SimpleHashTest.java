package org.tinycloud.security.util.secure;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * SimpleHash 通用哈希工具测试。
 *
 * <p>用标准向量锁定算法正确性（MD5("123456") 无盐单次），并验证加盐/迭代/输出格式行为。
 */
class SimpleHashTest {

    @Test
    void md5ShouldMatchKnownDigest() {
        // MD5("123456") 的通用标准值
        SimpleHash hash = new SimpleHash("MD5", "123456");

        assertEquals("e10adc3949ba59abbe56e057f20f883e", hash.toHex());
    }

    @Test
    void sha256ShouldMatchKnownDigest() {
        // SHA-256("abc") 的通用标准值
        SimpleHash hash = new SimpleHash("SHA-256", "abc");

        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash.toHex());
    }

    @Test
    void iterationsShouldChangeResult() {
        SimpleHash once = new SimpleHash("SHA-256", "password", "salt", 1);
        SimpleHash twice = new SimpleHash("SHA-256", "password", "salt", 2);

        assertNotEquals(once.toHex(), twice.toHex());
    }

    @Test
    void saltShouldChangeResult() {
        SimpleHash withSalt = new SimpleHash("SHA-256", "password", "salt-1", 1);
        SimpleHash withoutSalt = new SimpleHash("SHA-256", "password", null, 1);

        assertNotEquals(withSalt.toHex(), withoutSalt.toHex());
    }

    @Test
    void base64OutputShouldBeStable() {
        SimpleHash hash = new SimpleHash("MD5", "123456");

        assertEquals(
                java.util.Base64.getEncoder().encodeToString(
                        java.util.HexFormat.of().parseHex(hash.toHex())),
                hash.toBase64());
    }

    @Test
    void shouldRejectIterationsBelowOne() {
        assertThrows(IllegalArgumentException.class,
                () -> new SimpleHash("MD5", "password", null, 0));
    }
}
