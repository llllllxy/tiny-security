package org.tinycloud.security.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *     jwt 工具类
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-12-17 21:43
 */
public class JwtUtil {
    final static Logger log = LoggerFactory.getLogger(JwtUtil.class);

    // jwt默认subject
    private static final String JWT_SUBJECT = "tiny-security";

    // jwt默认有效期（秒）：30天
    private static final long JWT_DEFAULT_EXPIRE_SECONDS = 30L * 24 * 60 * 60;

    /**
     * 获取subject（不验签，仅解析）。
     *
     * <p><b>安全警告：</b>此方法不校验 JWT 签名，任何未签名/伪造的 token 也能被解析出 subject。
     * 若用于身份判断必须使用 {@link #getVerifiedSubject(String, String)}（验签），
     * 或对能拿到完整 claims 的业务直接使用 {@link #getClaims(String, String)}。
     *
     * @param jwtSign 签名值
     * @return subject
     * @deprecated 该方法不验签，存在被伪造 token 误导的安全风险，请改用 {@link #getVerifiedSubject(String, String)}
     */
    @Deprecated
    public static String getSubject(String jwtSign) {
        try {
            DecodedJWT jwt = JWT.decode(jwtSign);
            return jwt.getSubject();
        } catch (Exception e) {
            log.error("getSubject error：", e);
            return null;
        }
    }

    /**
     * 验签并获取 subject。
     *
     * <p>先使用密钥校验 JWT 签名与有效期，再返回 subject；验签失败（签名非法/已过期/密钥不符）返回 null。
     *
     * @param jwtSecret 密钥信息（不可为空）
     * @param jwtSign   签名值
     * @return subject，验签不通过时为 null
     */
    public static String getVerifiedSubject(String jwtSecret, String jwtSign) {
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("The jwtSecret cannot be empty! Please configure tiny-security.jwt-secret.");
        }
        try {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(jwtSecret)).build().verify(jwtSign);
            return jwt.getSubject();
        } catch (Exception e) {
            log.error("getVerifiedSubject error：", e);
            return null;
        }
    }

    /**
     * 验证jwt，并且解析里面的信息
     *
     * @param jwtSecret 密钥信息（不可为空）
     * @param jwtSign   签名值
     * @return claims信息，当为null时，说明验证不通过
     */
    public static Map<String, String> getClaims(String jwtSecret, String jwtSign) {
        // 校验密钥非空，禁止静默回退到任何内置默认密钥。
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("The jwtSecret cannot be empty! Please configure tiny-security.jwt-secret.");
        }
        try {
            Map<String, String> map = new HashMap<>();
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(jwtSecret)).build().verify(jwtSign);
            Map<String, Claim> claims = jwt.getClaims();
            claims.forEach((k, v) -> map.put(k, v.asString()));

            map.put("exp", String.valueOf(jwt.getExpiresAt().getTime()));
            map.put("iat", String.valueOf(jwt.getIssuedAt().getTime()));
            return map;
        } catch (Exception e) {
            log.error("getClaims error：", e);
            return null;
        }
    }

    /**
     * 生成 token（默认有效期30天）
     *
     * @param jwtSecret 密钥信息（不可为空）
     * @param subject   主题
     * @param payload   jwt其他数据（不可为空，可为空 Map）
     * @return token
     */
    public static String sign(String jwtSecret, String subject, Map<String, String> payload) {
        return sign(jwtSecret, subject, payload, JWT_DEFAULT_EXPIRE_SECONDS);
    }

    /**
     * 生成 token
     *
     * @param jwtSecret     密钥信息（不可为空）
     * @param subject       主题
     * @param payload       jwt其他数据（不可为 null）
     * @param expireSeconds token有效期（秒）
     * @return token
     */
    public static String sign(String jwtSecret, String subject, Map<String, String> payload, long expireSeconds) {
        // 校验密钥非空，禁止静默回退到任何内置默认密钥。
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("The jwtSecret cannot be empty! Please configure tiny-security.jwt-secret.");
        }
        // 校验 payload 非空，避免调用方传入 null 触发 NPE。
        if (payload == null) {
            throw new IllegalArgumentException("The payload cannot be null!");
        }
        if (subject == null || subject.isEmpty()) {
            subject = JWT_SUBJECT;
        }
        Date createTime = new Date();
        Date expireTime = new Date(createTime.getTime() + expireSeconds * 1000);
        JWTCreator.Builder builder = JWT.create();
        payload.forEach(builder::withClaim);
        return builder.withSubject(subject)
                .withIssuedAt(createTime)
                .withExpiresAt(expireTime)
                .sign(Algorithm.HMAC256(jwtSecret));
    }
}
