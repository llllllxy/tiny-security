package org.tinycloud.security.util;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.tinycloud.security.exception.TinySecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * token 签名工具类：用密钥为会话凭证生成不可伪造的签名。
 *
 * <p>token 中「签名部分」的形态为 {@code credentials.signature}，其中 signature 是
 * {@code base64url(HMAC-SHA256(credentials, secret))}。校验时先用密钥重算签名并做
 * 常量时间比对，通过后才取出 credentials 交给会话仓储判定会话是否有效。
 *
 * <p><b>它替代了原先的 JWT 封装</b>，只保留「签名防伪造」这一件事，因此：
 * <ul>
 *     <li>没有 payload 编解码：JWT 当初只装了一个 credentials，编解码纯属开销；</li>
 *     <li>没有第二条过期时间线：有效期一律以会话仓储为准，不再有 jwt-timeout 与 timeout 取较大值的问题；</li>
 *     <li>零第三方依赖：{@code javax.crypto} 是 JDK 自带，不像 JWT 需要引入 java-jwt；</li>
 *     <li>没有算法混淆面：算法在代码里写死为 HmacSHA256，不存在 alg=none 之类的绕过手法。</li>
 * </ul>
 *
 * <p><b>它保护什么、不保护什么：</b>
 * <ul>
 *     <li>保护：攻击者即便猜中了一个活着的 credentials，没有密钥也构造不出能通过校验的 token；
 *         同时垃圾 token 在本地就被拒绝，不会穿透到会话仓储（避免无效流量放大成存储压力）。</li>
 *     <li>不保护：会话是否有效仍完全由会话仓储判定，签名不是第二道授权判定；
 *         也完全不解决「credentials 本身被猜中/枚举」的问题，那取决于凭证本身的随机性强度
 *         （框架固定用 {@code UUID.randomUUID()}，内部走 SecureRandom）。</li>
 * </ul>
 *
 * @author liuxingyu01
 * @since 2026-09-30
 */
public class TokenSignUtil {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * credentials 与签名之间的分隔符。
     * credentials（UUID 去横线后的十六进制串）与 base64url 的字母表都不含该字符，因此可作为安全的分隔符。
     */
    private static final char SEPARATOR = '.';

    private TokenSignUtil() {
    }

    /**
     * 为会话凭证生成签名。
     *
     * @param secret      签名密钥（不可为空）
     * @param credentials 会话凭证（不可为空）
     * @return {@code credentials.signature}
     */
    public static String sign(String secret, String credentials) {
        Assert.hasText(secret, "The tokenSecret cannot be empty! Please configure tiny-security.token-secret.");
        Assert.hasText(credentials, "The credentials cannot be empty!");
        return credentials + SEPARATOR + encode(hmac(secret, credentials));
    }

    /**
     * 校验签名并取出会话凭证。
     *
     * @param secret 签名密钥（不可为空）
     * @param token  待校验的 token（不含 {@code Bearer } 前缀）
     * @return 校验通过时返回会话凭证；签名非法 / 格式非法 / 密钥不符时返回 null
     */
    public static String verifyAndExtract(String secret, String token) {
        Assert.hasText(secret, "The tokenSecret cannot be empty! Please configure tiny-security.token-secret.");
        if (!StringUtils.hasText(token)) {
            return null;
        }
        // credentials 与 base64url 都不含分隔符，故取最后一个分隔符即可，无需担心 credentials 中出现分隔符
        int separatorIndex = token.lastIndexOf(SEPARATOR);
        // 分隔符不存在，或位于首/尾（credentials 或签名部分为空）时，一律视为非法 token
        if (separatorIndex <= 0 || separatorIndex == token.length() - 1) {
            return null;
        }
        String credentials = token.substring(0, separatorIndex);
        String signature = token.substring(separatorIndex + 1);
        // 用常量时间比对，避免通过响应耗时逐字节爆破签名
        if (MessageDigest.isEqual(hmac(secret, credentials), decode(signature))) {
            return credentials;
        }
        return null;
    }

    /**
     * 计算 HMAC-SHA256。
     *
     * @param secret      签名密钥
     * @param credentials 会话凭证
     * @return 摘要字节
     */
    private static byte[] hmac(String secret, String credentials) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return mac.doFinal(credentials.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            // HmacSHA256 属于 JDK 必须支持的算法，正常环境不会走到这里；一旦发生说明运行环境异常，必须显式失败
            throw new TinySecurityException("Failed to compute the token signature!", e);
        }
    }

    /**
     * 字节摘要转 base64url 字符串（去掉填充符，可直接放在 URL 与请求头中）。
     *
     * @param bytes 摘要字节
     * @return base64url 字符串
     */
    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * base64url 字符串转字节摘要；格式非法时返回空数组（与任何签名都不相等，从而校验失败）。
     *
     * @param signature base64url 字符串
     * @return 摘要字节，格式非法时为空数组
     */
    private static byte[] decode(String signature) {
        try {
            return Base64.getUrlDecoder().decode(signature);
        } catch (IllegalArgumentException e) {
            return new byte[0];
        }
    }
}
