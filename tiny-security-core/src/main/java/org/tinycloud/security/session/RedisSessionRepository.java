package org.tinycloud.security.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.util.JsonUtil;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Redis 会话仓储实现
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class RedisSessionRepository implements SessionRepository {
    private static final Logger log = LoggerFactory.getLogger(RedisSessionRepository.class);

    private final StringRedisTemplate redisTemplate;

    /**
     * 构造 Redis 会话仓储。
     *
     * @param redisTemplate Redis 操作模板
     */
    public RedisSessionRepository(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 保存会话并记录在线凭证。
     */
    @Override
    public boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins) {
        Assert.notNull(subject, "The subject cannot be null!");
        Assert.hasText(subject.getCredentials(), "The credentials cannot be empty!");
        Assert.notNull(subject.getLoginId(), "The loginId cannot be null!");
        try {
            boolean canLogin = checkMaxLoginLimit(subject.getLoginId(), maxConcurrentLogins);
            if (!canLogin) {
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + maxConcurrentLogins + ") reached for the account; further logins are prohibited!");
            }
            String credentials = subject.getCredentials();
            this.addToOnlineList(subject.getLoginId(), credentials, maxConcurrentLogins);
            this.redisTemplate.opsForValue().set(
                    AuthConsts.AUTH_CREDENTIALS_KEY + credentials,
                    JsonUtil.writeValueAsString(subject),
                    timeoutSeconds,
                    TimeUnit.SECONDS
            );
            return true;
        } catch (ConcurrentLoginOverLimitException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("RedisSessionRepository save failed, Exception：", e);
            return false;
        }
    }

    /**
     * 检查指定凭证是否有效。
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return this.redisTemplate.hasKey(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
        } catch (Exception e) {
            log.error("RedisSessionRepository checkByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证读取登录主体。
     */
    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String content = this.redisTemplate.opsForValue().get(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return content == null ? null : JsonUtil.readValue(content, LoginSubject.class);
        } catch (Exception e) {
            log.error("RedisSessionRepository getSubject failed, Exception：", e);
            return null;
        }
    }

    /**
     * 刷新指定凭证会话。
     */
    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            this.redisTemplate.opsForValue().set(
                    AuthConsts.AUTH_CREDENTIALS_KEY + credentials,
                    JsonUtil.writeValueAsString(subject),
                    timeoutSeconds,
                    TimeUnit.SECONDS
            );
            return true;
        } catch (Exception e) {
            log.error("RedisSessionRepository refreshByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 删除指定凭证会话。
     */
    @Override
    public boolean deleteByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            LoginSubject subject = this.getSubject(credentials);
            if (subject != null) {
                this.removeFromOnlineList(subject.getLoginId(), credentials);
            }
            return this.redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
        } catch (Exception e) {
            log.error("RedisSessionRepository deleteByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 删除指定账号下全部会话。
     */
    @Override
    public boolean deleteByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        try {
            String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
            List<String> credentialsList = this.redisTemplate.opsForList().range(onlineKey, 0, -1);
            if (credentialsList == null || credentialsList.isEmpty()) {
                return false;
            }
            for (String cred : credentialsList) {
                redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
            }
            this.redisTemplate.delete(onlineKey);
            return true;
        } catch (Exception e) {
            log.error("RedisSessionRepository deleteByLoginId failed, Exception：", e);
            return false;
        }
    }

    /**
     * 统计指定账号有效在线会话数。
     */
    @Override
    public int countValidOnlineSessions(Object loginId) {
        List<String> validCredentials = this.clearInvalidCredentials(loginId);
        return validCredentials.size();
    }

    /**
     * 清理在线列表中的失效凭证并返回有效凭证。
     */
    private List<String> clearInvalidCredentials(Object loginId) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
        List<String> credentialsList = this.redisTemplate.opsForList().range(onlineKey, 0, -1);
        if (credentialsList == null || credentialsList.isEmpty()) {
            this.redisTemplate.delete(onlineKey);
            return Collections.emptyList();
        }
        List<String> invalidCredentials = credentialsList.stream()
                .filter(cred -> !this.redisTemplate.hasKey(AuthConsts.AUTH_CREDENTIALS_KEY + cred))
                .collect(Collectors.toList());
        if (!invalidCredentials.isEmpty()) {
            for (String invalidCred : invalidCredentials) {
                this.redisTemplate.opsForList().remove(onlineKey, 1, invalidCred);
            }
            credentialsList = this.redisTemplate.opsForList().range(onlineKey, 0, -1);
        }
        if (credentialsList == null || credentialsList.isEmpty()) {
            this.redisTemplate.delete(onlineKey);
            return Collections.emptyList();
        }
        return credentialsList;
    }

    /**
     * 判断账号是否达到并发登录上限。
     */
    private boolean checkMaxLoginLimit(Object loginId, int maxConcurrentLogins) {
        if (maxConcurrentLogins <= 0) {
            return true;
        }
        int currentOnlineCount = countValidOnlineSessions(loginId);
        log.info("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxConcurrentLogins);
        return currentOnlineCount < maxConcurrentLogins;
    }

    /**
     * 将凭证加入账号在线列表。
     */
    private void addToOnlineList(Object loginId, String credentials, int maxConcurrentLogins) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
        this.redisTemplate.opsForList().rightPush(onlineKey, credentials);
        if (maxConcurrentLogins > 0) {
            Long size = this.redisTemplate.opsForList().size(onlineKey);
            if (size != null && size > maxConcurrentLogins) {
                this.redisTemplate.opsForList().remove(onlineKey, 1, credentials);
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + maxConcurrentLogins + ") reached for the account; further logins are prohibited!");
            }
        }
    }

    /**
     * 从账号在线列表中移除凭证。
     */
    private void removeFromOnlineList(Object loginId, String credentials) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
        long removeCount = this.redisTemplate.opsForList().remove(onlineKey, 1, credentials);
        if (removeCount > 0) {
            Long size = this.redisTemplate.opsForList().size(onlineKey);
            if (size != null && size == 0) {
                this.redisTemplate.delete(onlineKey);
            }
        }
    }
}
