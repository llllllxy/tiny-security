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

    /**
     * P0-7 回归：salt=null 必须归一化为空串，而不是被拼成字面量 {@code "null"}。
     * 修复前 {@code (source + salt)} 会让 {@code salt=null} 与 {@code salt="null"} 产生同一哈希（真碰撞）。
     */
    @Test
    void nullSaltShouldBeTreatedAsEmptyNotNullLiteral() {
        SM3Hash nullSalt = new SM3Hash("password", null);
        SM3Hash emptySalt = new SM3Hash("password", "");
        SM3Hash literalNullSalt = new SM3Hash("password", "null");

        // null 与 "" 等价
        assertEquals(emptySalt.toHex(), nullSalt.toHex());
        // 且不再与字面量 "null" 碰撞
        assertNotEquals(literalNullSalt.toHex(), nullSalt.toHex());
    }

    /**
     * P0-7 回归：{@code setSalt(null)} 与不设 salt（字段默认 {@code ""}）应得到相同结果。
     */
    @Test
    void setNullSaltShouldMatchDefaultSalt() {
        SM3Hash defaultSalt = new SM3Hash("password");
        SM3Hash setNullSalt = new SM3Hash("password");
        setNullSalt.setSalt(null);

        assertEquals(defaultSalt.toHex(), setNullSalt.toHex());
    }

    /**
     * P0-7 回归：三参构造传入 null salt 与 {@code ""} 等价（走的是同一条归一化路径）。
     */
    @Test
    void nullSaltWithIterationsShouldMatchEmptySalt() {
        assertEquals(new SM3Hash("password", "", 3).toHex(), new SM3Hash("password", null, 3).toHex());
    }
}
