package org.tinycloud.security.util.secure;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

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

    /**
     * 回归：SM3 分支的 {@code salt=null} 现在与 JDK 分支语义一致（都视为不加盐），
     * 不再被拼成字面量 {@code "null"} 而与 {@code salt="null"} 碰撞。
     */
    @Test
    void sm3BranchShouldTreatNullSaltAsEmptyLikeJdkBranch() {
        SimpleHash sm3Null = new SimpleHash("SM3", "password", null, 1);
        SimpleHash sm3Empty = new SimpleHash("SM3", "password", "", 1);
        SimpleHash sm3LiteralNull = new SimpleHash("SM3", "password", "null", 1);

        assertEquals(sm3Empty.toHex(), sm3Null.toHex());
        assertNotEquals(sm3LiteralNull.toHex(), sm3Null.toHex());

        // JDK 分支的既有语义：null salt 等同于不加盐（作为对齐基准）
        assertEquals(new SimpleHash("SHA-256", "password", "", 1).toHex(),
                new SimpleHash("SHA-256", "password", null, 1).toHex());
    }
}
