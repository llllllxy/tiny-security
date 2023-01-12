package org.bluewind.authclient.provider;


import org.bluewind.authclient.AuthProperties;
import org.bluewind.authclient.consts.AuthConsts;
import org.bluewind.authclient.util.AuthUtil;
import org.bluewind.authclient.util.CookieUtil;
import org.bluewind.authclient.util.Snowflake;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


/**
 * 操作token和会话的接口（通过redis实现）
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class RedisAuthProvider implements AuthProvider {
    final static Logger log = LoggerFactory.getLogger(RedisAuthProvider.class);

    private final StringRedisTemplate redisTemplate;
    private final AuthProperties authProperties;

    public RedisAuthProvider(StringRedisTemplate redisTemplate, AuthProperties authProperties) {
        this.redisTemplate = redisTemplate;
        this.authProperties = authProperties;
    }

    /**
     * 刷新token
     *
     * @param token
     * @return
     */
    @Override
    public boolean refreshToken(String token) {
        try {
            return redisTemplate.expire(AuthConsts.AUTH_TOKEN_KEY + token, authProperties.getTimeout(), TimeUnit.SECONDS);
        } catch (Exception e) {
            log.error("RedisAuthProvider - refreshToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 检查token是否失效
     *
     * @param token
     * @return
     */
    @Override
    public boolean checkToken(String token) {
        try {
            return redisTemplate.hasKey(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthProvider - checkToken - 失败，Exception：{e}", e);
            return false;
        }
    }


    /**
     * 创建一个新的token
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    @Override
    public String createToken(Object loginId) {
        try {
            String token;
            if (TOKEN_STYLE_SNOWFLAKE.equals(authProperties.getTokenStyle())) {
                token = Snowflake.nextId();
            } else {
                token = UUID.randomUUID().toString().replaceAll("-", "");
            }
            redisTemplate.opsForValue().set(AuthConsts.AUTH_TOKEN_KEY + token, String.valueOf(loginId), authProperties.getTimeout(), TimeUnit.SECONDS);
            return token;
        } catch (Exception e) {
            log.error("RedisAuthProvider - createToken - 失败，Exception：{e}", e);
            return null;
        }
    }


    /**
     * 根据token，获取loginId
     *
     * @param token
     * @return
     */
    @Override
    public Object getLoginId(String token) {
        try {
            return redisTemplate.opsForValue().get(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthProvider - getLoginId - 失败，Exception：{e}", e);
            return null;
        }
    }

    /**
     * 删除token
     *
     * @param token
     * @return
     */
    @Override
    public boolean deleteToken(String token) {
        try {
            return redisTemplate.delete(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthProvider - deleteToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 通过loginId删除token（通过keys命令模糊查询的，数据量大时会有性能问题，后续优化）
     *
     * @param loginId
     * @return
     */
    @Override
    public boolean deleteTokenByLoginId(Object loginId) {
        try {
            Set<String> keys = redisTemplate.keys(AuthConsts.AUTH_TOKEN_KEY.concat("*"));
            if (Objects.nonNull(keys) && !keys.isEmpty()) {
                for (String key : keys) {
                    String loginIdInRedis = redisTemplate.opsForValue().get(key);
                    if (!StringUtils.isEmpty(loginIdInRedis) && loginIdInRedis.equals(loginId)) {
                        redisTemplate.delete(key);
                    }
                }
            }
            return true;
        } catch (Exception e) {
            log.error("RedisAuthProvider - deleteToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     */
    @Override
    public String login(Object loginId) {
        String token = this.createToken(loginId);
        // 设置 Cookie，通过 Cookie 上下文返回给前端
        CookieUtil.setCookie(AuthUtil.getResponse(), this.authProperties.getTokenName(), token);
        return token;
    }

    /**
     * 退出登录
     */
    @Override
    public void logout(HttpServletRequest request) {
        String token = AuthUtil.getToken(request, this.authProperties.getTokenName());
        this.deleteToken(token);
    }

    /**
     * 退出登录
     */
    @Override
    public void logout() {
        String token = AuthUtil.getToken(this.authProperties.getTokenName());
        this.deleteToken(token);
    }

    /**
     * 获取当前登录用户的loginId
     *
     * @return
     */
    @Override
    public Object getLoginId() {
        try {
            String token = AuthUtil.getToken(this.authProperties.getTokenName());
            return redisTemplate.opsForValue().get(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthProvider - getLoginId - 失败，Exception：{e}", e);
            return null;
        }
    }
}
