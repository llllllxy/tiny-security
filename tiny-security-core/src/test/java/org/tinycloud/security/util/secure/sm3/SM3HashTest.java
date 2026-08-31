package org.tinycloud.security.util.secure.sm3;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * SM3 国密哈希测试：用国家密码管理局标准测试向量锁定算法正确性。
 *
 * <p>标准向量：SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
 */
class SM3HashTest {

    @Test
    void sm3ShouldMatchStandardTestVector() {
        // 国密标准测试向量：SM3("abc")
        SM3Hash hash = new SM3Hash("abc");

        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", hash.toHex());
    }

    @Test
    void sm3ShouldMatchEmptyStringVector() {
        // 国密标准测试向量：SM3("")
        SM3Hash hash = new SM3Hash("");

        assertEquals("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", hash.toHex());
    }

    @Test
    void saltShouldChangeResult() {
        SM3Hash noSalt = new SM3Hash("password");
        SM3Hash withSalt = new SM3Hash("password", "salt-1", 1);

        assertNotEquals(noSalt.toHex(), withSalt.toHex());
    }

    @Test
    void iterationsShouldChangeResult() {
        SM3Hash once = new SM3Hash("password", "salt", 1);
        SM3Hash twice = new SM3Hash("password", "salt", 2);

        assertNotEquals(once.toHex(), twice.toHex());
    }

    @Test
    void base64ShouldBeStable() {
        SM3Hash hash = new SM3Hash("abc");

        assertEquals(
                java.util.Base64.getEncoder().encodeToString(
                        java.util.HexFormat.of().parseHex(hash.toHex())),
                hash.toBase64());
    }
}
