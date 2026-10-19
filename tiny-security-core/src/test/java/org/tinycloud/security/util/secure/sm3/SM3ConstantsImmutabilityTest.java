package org.tinycloud.security.util.secure.sm3;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SM3} 常量不可被外部污染的回归测试。
 *
 * <p>此前 {@code SM3.iv}（{@code byte[]}）与 {@code SM3.Tj}（{@code int[]}）都是
 * {@code public static} 数组 —— {@code final} 只锁引用，挡不住 {@code iv[0] = x}。
 * 任何代码都能改写它们，之后**所有** SM3 摘要都会算错，且不会有任何异常或日志。
 *
 * <p>现在两者改为包内私有，测试从三个角度锁定：
 * <ol>
 *     <li>字段可见性不再对外暴露（反射校验非 public）；</li>
 *     <li>同一输入多次摘要结果稳定（常量没有被某次计算改写）；</li>
 *     <li>标准测试向量仍然正确（确认收窄可见性没有改变算法）。</li>
 * </ol>
 *
 * @author liuxingyu01
 */
class SM3ConstantsImmutabilityTest {

    /**
     * 常量字段不得是 public —— 否则外部代码可直接改写数组内容。
     */
    @Test
    void constantsShouldNotBePublic() throws Exception {
        for (String name : new String[]{"iv", "Tj"}) {
            Field field = SM3.class.getDeclaredField(name);
            assertFalse(Modifier.isPublic(field.getModifiers()),
                    name + " 不应是 public：final 只锁引用，数组内容仍可被外部改写");
        }
    }

    /**
     * 同一输入连续摘要多次，结果必须完全一致。
     *
     * <p>若某次 {@code CF} 意外改写了 {@code iv} / {@code Tj}，这里会立刻发现。
     */
    @Test
    void repeatedDigestShouldBeStable() {
        String first = digest("abc");
        for (int i = 0; i < 5; i++) {
            assertEquals(first, digest("abc"), "同一输入的摘要结果必须稳定");
        }
    }

    /**
     * 不同输入之间不得相互影响（防止共享状态串味）。
     */
    @Test
    void interleavedDigestsShouldNotAffectEachOther() {
        String abc = digest("abc");
        String abd = digest("abd");

        assertNotEquals(abc, abd, "不同输入应有不同摘要");
        assertEquals(abc, digest("abc"), "中间插入其它计算后，原输入结果不应改变");
    }

    /**
     * 标准测试向量（GM/T 0004-2012）：确认可见性收窄没有影响算法本身。
     */
    @Test
    void shouldMatchStandardVector() {
        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", digest("abc"));
        // 864 bit（16 个 "abcd"，共 64 字节）
        assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                digest("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"));
    }

    private static String digest(String input) {
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        StringBuilder sb = new StringBuilder();
        for (byte b : out) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
