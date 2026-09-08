package org.tinycloud.security.session;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import org.checkerframework.checker.index.qual.NonNegative;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

/**
 * 基于 Caffeine 本地缓存的会话仓储实现。
 *
 * <p>与 {@link SingleSessionRepository} 同属本地内存存储，但额外提供：
 * <ul>
 *     <li><b>容量上限保护</b>（{@code caffeine-maximum-size}，默认 10000）：避免会话无限累积撑爆内存</li>
 *     <li>成熟的惰性过期驱逐 + 缓存统计</li>
 * </ul>
 *
 * <p>过期语义：每个凭证的存活时间取自 {@link LoginSubject#getLoginExpireTime()}（与 Single/JDBC/Redis
 * 一致，由框架会话 timeout 驱动）；续期（refresh）时重新 put 会重置过期时间。
 *
 * <p><b>可选依赖</b>：caffeine 以 provided 提供，使用 {@code store-type=caffeine} 时需自行引入：
 * <pre>{@code
 * <dependency>
 *     <groupId>com.github.ben-manes.caffeine</groupId>
 *     <artifactId>caffeine</artifactId>
 * </dependency>
 * }</pre>
 *
 * @author liuxingyu01
 */
public class CaffeineSessionRepository implements SessionRepository, DisposableBean {
    private static final Logger log = LoggerFactory.getLogger(CaffeineSessionRepository.class);

    /**
     * 会话核心缓存：key=凭证，value=登录主体。过期时间由 loginExpireTime 驱动。
     */
    private final Cache<String, LoginSubject> cache;

    /**
     * key: loginId（转为String），value: 该账号的所有在线凭证列表
     */
    private final Map<String, List<String>> loginIdToCredentialsMap = new ConcurrentHashMap<>();

    /**
     * 保护 {@link #loginIdToCredentialsMap} 及其 list 变更的锁。
     */
    private final Object onlineLock = new Object();

    /**
     * 构造 Caffeine 会话仓储。
     *
     * @param maximumSize 缓存最大条目数（超出后按 LRU 驱逐最早写入的会话）
     */
    public CaffeineSessionRepository(long maximumSize) {
        Assert.isTrue(maximumSize > 0, "The caffeine maximum size must be > 0!");
        this.cache = Caffeine.newBuilder()
                .maximumSize(maximumSize)
                // 每个 key 的存活时间 = 会话 loginExpireTime - now；已过期立即驱逐
                .expireAfter(new Expiry<String, LoginSubject>() {
                    @Override
                    public long expireAfterCreate(String key, LoginSubject value, long currentTime) {
                        return nanosUntilExpire(value);
                    }

                    @Override
                    public long expireAfterUpdate(String key, LoginSubject value, long currentTime,
                                                  @NonNegative long currentDuration) {
                        // 续期/重写后按新的 loginExpireTime 重新计算
                        return nanosUntilExpire(value);
                    }

                    @Override
                    public long expireAfterRead(String key, LoginSubject value, long currentTime,
                                                @NonNegative long currentDuration) {
                        // 读不重置过期时间：滑动续期由框架的 refresh 显式驱动（与其它仓储语义一致）
                        return currentDuration;
                    }
                })
                .build();
    }

    /**
     * 计算距离会话过期剩余纳秒数；已过期返回 0（立即驱逐）。
     */
    private static long nanosUntilExpire(LoginSubject subject) {
        long expireTime = subject.getLoginExpireTime();
        long remainingMillis = expireTime - System.currentTimeMillis();
        return Math.max(0L, remainingMillis) * 1_000_000L;
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
            // 无论是否启用并发限制，登录时都清理该账号在线索引中的失效凭证，否则索引随登录次数无限累积（内存泄漏）
            this.countValidOnlineSessions(subject.getLoginId());
            this.cache.put(AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials(), subject);
            this.addToOnlineList(subject.getLoginId(), subject.getCredentials());
            return true;
        } catch (ConcurrentLoginOverLimitException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("CaffeineSessionRepository save failed, Exception：", e);
            return false;
        }
    }

    /**
     * 检查指定凭证是否有效（Caffeine 惰性驱逐：已过期条目 getIfPresent 返回 null）。
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return this.cache.getIfPresent(AuthConsts.AUTH_CREDENTIALS_KEY + credentials) != null;
        } catch (Exception e) {
            log.error("CaffeineSessionRepository checkByCredentials failed, Exception：", e);
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
            return this.cache.getIfPresent(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
        } catch (Exception e) {
            log.error("CaffeineSessionRepository getSubject failed, Exception：", e);
            return null;
        }
    }

    /**
     * 刷新指定凭证会话（重新 put 触发 expireAfterUpdate，按新 loginExpireTime 重置过期）。
     */
    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            this.cache.put(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, subject);
            return true;
        } catch (Exception e) {
            log.error("CaffeineSessionRepository refreshByCredentials failed, Exception：", e);
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
            this.cache.invalidate(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return true;
        } catch (Exception e) {
            log.error("CaffeineSessionRepository deleteByCredentials failed, Exception：", e);
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
            String loginIdStr = String.valueOf(loginId);
            List<String> credentialsList;
            synchronized (onlineLock) {
                credentialsList = this.loginIdToCredentialsMap.get(loginIdStr);
                this.loginIdToCredentialsMap.remove(loginIdStr);
            }
            if (credentialsList != null && !credentialsList.isEmpty()) {
                for (String cred : credentialsList) {
                    this.cache.invalidate(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
                }
            }
            return true;
        } catch (Exception e) {
            log.error("CaffeineSessionRepository deleteByLoginId failed, Exception：", e);
            return false;
        }
    }

    /**
     * 统计指定账号有效在线会话数，并清理失效凭证索引。
     */
    @Override
    public int countValidOnlineSessions(Object loginId) {
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            List<String> credentialsList = this.loginIdToCredentialsMap.get(loginIdStr);
            if (credentialsList == null || credentialsList.isEmpty()) {
                return 0;
            }
            // 就地移除已被 Caffeine 驱逐的失效凭证，不替换 list 引用（并发 add 不会丢失）
            credentialsList.removeIf(cred -> this.cache.getIfPresent(AuthConsts.AUTH_CREDENTIALS_KEY + cred) == null);
            if (credentialsList.isEmpty()) {
                this.loginIdToCredentialsMap.remove(loginIdStr);
                return 0;
            }
            return credentialsList.size();
        }
    }

    /**
     * 判断账号是否达到并发登录上限。
     */
    private boolean checkMaxLoginLimit(Object loginId, int maxConcurrentLogins) {
        if (maxConcurrentLogins <= 0) {
            return true;
        }
        int currentOnlineCount = countValidOnlineSessions(loginId);
        log.debug("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxConcurrentLogins);
        return currentOnlineCount < maxConcurrentLogins;
    }

    /**
     * 将凭证加入账号在线列表。
     */
    private void addToOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            this.loginIdToCredentialsMap.computeIfAbsent(loginIdStr, k -> new CopyOnWriteArrayList<>()).add(credentials);
        }
    }

    /**
     * 从账号在线列表中移除凭证。
     */
    private void removeFromOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            List<String> credentialsList = loginIdToCredentialsMap.get(loginIdStr);
            if (credentialsList == null || credentialsList.isEmpty()) {
                return;
            }
            boolean removed = credentialsList.remove(credentials);
            if (removed && credentialsList.isEmpty()) {
                loginIdToCredentialsMap.remove(loginIdStr);
            }
        }
    }

    /**
     * 在 Spring 容器关闭时执行 Caffeine 缓存清理。
     */
    @Override
    public void destroy() {
        this.cache.cleanUp();
    }
}
