package org.bluewind.authclient.provider;


import org.bluewind.authclient.AuthProperties;
import org.bluewind.authclient.consts.AuthConsts;
import org.bluewind.authclient.util.Snowflake;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.UUID;
import java.util.concurrent.TimeUnit;


/**
 * 操作token的接口（通过redis实现）
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class RedisAuthStore implements AuthStore {
    final static Logger log = LoggerFactory.getLogger(RedisAuthStore.class);

    private final StringRedisTemplate redisTemplate;
    private final AuthProperties authProperties;

    public RedisAuthStore(StringRedisTemplate redisTemplate, AuthProperties authProperties) {
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
            log.error("RedisAuthStore - refreshToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 检查token是否失效
     * @param token
     * @return
     */
    @Override
    public boolean checkToken(String token) {
        try {
            return redisTemplate.hasKey(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthStore - checkToken - 失败，Exception：{e}", e);
            return false;
        }
    }



    /**
     * 创建一个新的token
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    @Override
    public String createToken(Object loginId) {
        try {
            String token;
            if (authProperties.getTokenStyle().equals(TOKENSTYLE_SNOWFLAKE)) {
                token = Snowflake.nextId();
            } else {
                token = UUID.randomUUID().toString().replaceAll("-", "");
            }
            redisTemplate.opsForValue().set(AuthConsts.AUTH_TOKEN_KEY + token, String.valueOf(loginId), authProperties.getTimeout(), TimeUnit.SECONDS);
            return token;
        } catch (Exception e) {
            log.error("RedisAuthStore - createToken - 失败，Exception：{e}", e);
            return null;
        }
    }


    /**
     * 根据token，获取当前登录用户的loginId
     * @param token
     * @return
     */
    @Override
    public Object getLoginId(String token) {
        try {
            return redisTemplate.opsForValue().get(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthStore - getLoginId - 失败，Exception：{e}", e);
            return null;
        }
    }


    /**
     * 删除token
     * @param token
     * @return
     */
    @Override
    public boolean deleteToken(String token) {
        try {
            return redisTemplate.delete(AuthConsts.AUTH_TOKEN_KEY + token);
        } catch (Exception e) {
            log.error("RedisAuthStore - deleteToken - 失败，Exception：{e}", e);
            return false;
        }
    }


    /**
     * 通过loginId删除token
     * @param loginId
     * @return
     */
    @Override
    public boolean deleteTokenByLoginId(Object loginId) {
        return false;
    }


}
