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
     * 获取subject
     * <br/>
     * 只是简单的解析jwt里的数据并不需要验证签名
     *
     * @param jwtSign 签名值
     * @return subject
     */
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
     * @param payload   jwt其他数据
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
     * @param payload       jwt其他数据
     * @param expireSeconds token有效期（秒）
     * @return token
     */
    public static String sign(String jwtSecret, String subject, Map<String, String> payload, long expireSeconds) {
        // 校验密钥非空，禁止静默回退到任何内置默认密钥。
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            throw new IllegalArgumentException("The jwtSecret cannot be empty! Please configure tiny-security.jwt-secret.");
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
