package org.tinycloud.security.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

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

    // jwt签名密钥
    private static final String JWT_SECRET = "K$N)A3*sGGf<wo*22*%&(DF";

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
     * @param jwtSecret 密钥信息
     * @param jwtSign   签名值
     * @return claims信息，当为null时，说明验证不通过
     */
    public static Map<String, String> getClaims(String jwtSecret, String jwtSign) {
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            jwtSecret = JWT_SECRET;
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
     * 生成 token
     *
     * @param jwtSecret 密钥信息
     * @param subject   主题
     * @param payload   jwt其他数据
     * @return token
     */
    public static String sign(String jwtSecret, String subject, Map<String, String> payload) {
        if (jwtSecret == null || jwtSecret.isEmpty()) {
            jwtSecret = JWT_SECRET;
        }
        Date createTime = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(createTime);
        calendar.add(Calendar.DAY_OF_MONTH, 30); // 过期时间设置为30天后，即30天后强制过期
        Date expireTime = calendar.getTime();
        JWTCreator.Builder builder = JWT.create();
        payload.forEach(builder::withClaim);
        return builder.withSubject(subject)
                .withIssuedAt(createTime)
                .withExpiresAt(expireTime)
                .sign(Algorithm.HMAC256(jwtSecret));
    }

    public static void main(String[] args) {
        Map<String, String> map = new HashMap<>();
        map.put("token", UUID.randomUUID().toString());

        // 生成jwt签名值
        String token = sign(null, "x1cloud", map);
        System.out.println(token);

        // 解析jwt签名值
        System.out.println(getClaims(null, token));
    }
}
