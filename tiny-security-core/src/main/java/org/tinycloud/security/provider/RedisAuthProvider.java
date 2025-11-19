
package org.tinycloud.security.provider;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.util.JsonUtil;
import org.tinycloud.security.util.JwtUtil;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;


/**
 * 操作token和会话的接口（通过redis实现）
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class RedisAuthProvider extends AbstractAuthProvider implements AuthProvider {
    private final static Logger log = LoggerFactory.getLogger(RedisAuthProvider.class);

    private final StringRedisTemplate redisTemplate;

    public RedisAuthProvider(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 刷新会话
     *
     * @param credentials 凭证
     * @return true成功，false失败
     */
    @Override
    public boolean refreshByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return Boolean.TRUE.equals(this.redisTemplate.expire(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, GlobalConfigUtils.getGlobalConfig().getTimeout(), TimeUnit.SECONDS));
        } catch (Exception e) {
            log.error("RedisAuthProvider refreshByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 刷新token
     *
     * @param credentials 凭证
     * @param subject     登录用户
     * @return true成功，false失败
     */
    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            this.redisTemplate.opsForValue().set(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, JsonUtil.writeValueAsString(subject), GlobalConfigUtils.getGlobalConfig().getTimeout(), TimeUnit.SECONDS);
            return true;
        } catch (Exception e) {
            log.error("RedisAuthProvider refreshByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 检查凭证是否失效
     *
     * @param credentials 凭证
     * @return true未失效，false已失效
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return Boolean.TRUE.equals(this.redisTemplate.hasKey(AuthConsts.AUTH_CREDENTIALS_KEY + credentials));
        } catch (Exception e) {
            log.error("RedisAuthProvider checkByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证获取登录用户
     *
     * @param credentials 凭证
     * @return LoginSubject
     */
    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String content = this.redisTemplate.opsForValue().get(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            if (content == null) {
                return null;
            } else {
                return JsonUtil.readValue(content, LoginSubject.class);
            }
        } catch (Exception e) {
            log.error("RedisAuthProvider getSubject failed, Exception：", e);
            return null;
        }
    }


    /**
     * 创建一个新的token
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return token令牌
     */
    @Override
    public String createAuth(Object loginId, Map<String, Object> extraInfo) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        Assert.isTrue(loginId instanceof Number || loginId instanceof String, "loginId must be of type Number (Long, Integer, etc.) or String, but got: " + loginId.getClass().getName());
        try {
            String credentials = CredentialsGenUtil.generate(GlobalConfigUtils.getGlobalConfig().getCredentialsStyle());
            Map<String, String> payload = new HashMap<>();
            payload.put("credentials", credentials);
            String jwtToken = JwtUtil.sign(GlobalConfigUtils.getGlobalConfig().getJwtSecret(), GlobalConfigUtils.getGlobalConfig().getJwtSubject(), payload);

            LoginSubject subject = new LoginSubject();
            subject.setExtraInfo(extraInfo);
            subject.setLoginId(loginId);
            long currentTime = System.currentTimeMillis();
            subject.setLoginTime(currentTime);
            subject.setLoginExpireTime(currentTime + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000L);
            this.redisTemplate.opsForValue().set(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, JsonUtil.writeValueAsString(subject), GlobalConfigUtils.getGlobalConfig().getTimeout(), TimeUnit.SECONDS);
            return AuthConsts.JWT_TOKEN_PREFIX + jwtToken;
        } catch (Exception e) {
            log.error("RedisAuthProvider createAuth failed, Exception：", e);
            return null;
        }
    }

    /**
     * 根据token删除
     *
     * @param token 令牌
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByToken(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String credentials = this.getCredentialsByToken(token);
            return Boolean.TRUE.equals(this.redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + credentials));
        } catch (Exception e) {
            log.error("RedisAuthProvider deleteToken failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证删除
     *
     * @param credentials 凭证
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return Boolean.TRUE.equals(this.redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + credentials));
        } catch (Exception e) {
            log.error("RedisAuthProvider deleteByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 通过loginId删除token（通过scan命令模糊查询）
     *
     * @param loginId 身份唯一值
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        try {
            Set<String> keys = this.scanKeys(AuthConsts.AUTH_CREDENTIALS_KEY.concat("*"));
            if (Objects.nonNull(keys) && !keys.isEmpty()) {
                for (String key : keys) {
                    String content = this.redisTemplate.opsForValue().get(key);
                    LoginSubject subject = JsonUtil.readValue(content, LoginSubject.class);
                    if (Objects.nonNull(subject)
                            && Objects.nonNull(subject.getLoginId())
                            && subject.getLoginId().equals(loginId)) {
                        this.redisTemplate.delete(key);
                    }
                }
            }
            return true;
        } catch (Exception e) {
            log.error("RedisAuthProvider deleteByLoginId failed, Exception：", e);
            return false;
        }
    }


    /**
     * 使用scan命令查询所有符合给定模式(pattern)的key
     *
     * @param pattern 匹配
     * @return keys列表
     */
    public Set<String> scanKeys(String pattern) {
        Set<String> keys = new HashSet<>();
        // 参数校验：避免空模式扫描全量键
        if (pattern == null || pattern.trim().isEmpty()) {
            log.warn("Scan pattern is empty, return empty keys");
            return keys;
        }
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).count(100).build();
            // 执行扫描并获取游标（Cursor<byte[]> 需手动转为 String）
            try (Cursor<byte[]> cursor = connection.scan(options)) {
                while (cursor.hasNext()) {
                    keys.add(new String(cursor.next(), StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                log.error("Redis scanKeys failed, pattern: {}", pattern, e);
            }
            return null;
        });
        return keys;
    }
}
