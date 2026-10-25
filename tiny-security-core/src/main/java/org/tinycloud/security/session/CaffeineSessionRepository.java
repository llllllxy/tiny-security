package org.tinycloud.security.session;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 基于 Caffeine 本地缓存的会话仓储实现。
 *
 * <p>与 {@link SingleSessionRepository} 同属本地内存存储，但额外提供：
 * <ul>
 *     <li><b>容量上限保护</b>（{@code caffeine-maximum-size}，默认 10000）：避免会话无限累积撑爆内存</li>
 *     <li>成熟的惰性过期驱逐 + 缓存统计</li>
 * </ul>
 *
 * <p>过期语义：每个凭证的存活时间取自 {@link LoginSubject#getLoginExpireTime}（与 Single/JDBC/Redis
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
                                                  long currentDuration) {
                        // 续期/重写后按新的 loginExpireTime 重新计算
                        return nanosUntilExpire(value);
                    }

                    @Override
                    public long expireAfterRead(String key, LoginSubject value, long currentTime,
                                                long currentDuration) {
                        // 读不重置过期时间：滑动续期由框架的 refresh 显式驱动（与其它仓储语义一致）
                        return currentDuration;
                    }
                })
                .build();
    }

    /**
     * 计算距离会话过期剩余纳秒数；已过期返回 0（立即驱逐）。
     *
     * <p>{@code loginExpireTime} 为空说明仓储拿到的登录主体不完整（自定义 SessionRepository
     * 或反序列化缺字段），按"已过期"处理，与内核的判定口径保持一致，避免拆箱抛 NPE。
     */
    private static long nanosUntilExpire(LoginSubject subject) {
        Long expireTime = subject.getLoginExpireTime();
        if (expireTime == null) {
            return 0L;
        }
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
            // 凭证是随机生成的会话唯一钥匙，理论上不会重复。一旦重复，说明随机源异常或有人在构造会话固定攻击，
            // 此时必须明确失败，绝不能静默覆盖掉另一个用户的会话
            LoginSubject existing = this.cache.asMap()
                    .putIfAbsent(AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials(), subject);
            if (existing != null) {
                log.error("CaffeineSessionRepository save failed: credentials collision detected, the generated token already exists!");
                return false;
            }
            // 先写会话、再原子占名额，顺序不能颠倒：若先占名额，并发的清理逻辑会因为凭证还不存在
            // 而把刚加入的凭证误判为"失效"并移除
            if (!this.addToOnlineListIfLimitNotExceeded(subject.getLoginId(), subject.getCredentials(), maxConcurrentLogins)) {
                // 并发竞争下没抢到名额：必须回滚刚写入的会话，否则会留下一个绕过并发上限的可用会话
                this.cache.invalidate(AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials());
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + maxConcurrentLogins + ") reached for the account; further logins are prohibited!");
            }
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
     *
     * <p>返回**副本**：本仓储把对象引用存在缓存里，若直接返回缓存实例，调用方修改它（如
     * {@code setLoginExpireTime(...)}）会污染缓存并在后续请求中生效，而 redis/jdbc 仓储每次
     * 反序列化出新对象、不受影响 —— 同一份代码在四种仓储下语义会不一致。
     */
    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            LoginSubject cached = this.cache.getIfPresent(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return cached == null ? null : cached.copy();
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
     * 获取指定账号下全部有效（未被驱逐）会话凭证。
     * <p>在 {@link #onlineLock} 锁内先就地清理已被 Caffeine 驱逐的凭证，再返回列表副本。
     */
    @Override
    public List<String> getCredentialsByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            List<String> credentialsList = this.loginIdToCredentialsMap.get(loginIdStr);
            if (credentialsList == null || credentialsList.isEmpty()) {
                return new ArrayList<>();
            }
            credentialsList.removeIf(cred -> this.cache.getIfPresent(AuthConsts.AUTH_CREDENTIALS_KEY + cred) == null);
            if (credentialsList.isEmpty()) {
                this.loginIdToCredentialsMap.remove(loginIdStr);
                return new ArrayList<>();
            }
            return new ArrayList<>(credentialsList);
        }
    }

    /**
     * 获取全部在线账号ID（去重）。
     *
     * <p>与 {@link SingleSessionRepository#getOnlineLoginIds()} 同思路：遍历内存中的
     * "账号 → 凭证列表"索引，并逐个用 {@link #countValidOnlineSessions(Object)} 回查有效性，
     * 剔除"索引还在、但会话已被 Caffeine 驱逐"的账号（惰性清理，与仓储其它方法口径一致）。
     *
     * <p><b>多实例部署只能看到本实例</b>：{@code store-type=caffeine} 是本地缓存，
     * 每个 JVM 一份数据，这里的"全量"仅指本实例。需要全局视图请用 {@code redis} 或 {@code jdbc}。
     *
     * <p><b>容量上限会影响结果</b>：本仓储按 {@code caffeine-maximum-size}（默认 10000）做 LRU 驱逐，
     * 超过上限时最早写入的会话会被挤掉 —— 那时它们不在缓存里，自然也不会出现在线上列表中。
     *
     * <p>实现细节：遍历 keySet 的<b>副本</b>，因为 {@code countValidOnlineSessions} 会在账号
     * 凭证全部失效时从 map 中移除该账号，直接迭代 keySet 会触发 {@code ConcurrentModificationException}。
     *
     * @return 存在有效会话的账号ID列表（去重，元素为 String）；无在线账号时返回空列表
     */
    @Override
    public List<Object> getOnlineLoginIds() {
        Set<String> loginIds = new LinkedHashSet<>();
        for (String loginId : new ArrayList<>(this.loginIdToCredentialsMap.keySet())) {
            if (loginId != null && this.countValidOnlineSessions(loginId) > 0) {
                loginIds.add(loginId);
            }
        }
        return new ArrayList<>(loginIds);
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
     * 原子地判断并发上限并把凭证加入账号在线列表。
     *
     * <p>"判断上限"与"入列"必须在**同一把锁**内完成，否则并发登录会得到两种错误结果：
     * 都通过上限判断后各自入列 → 实际在线数突破上限；或都入列后各自发现超额、各自摘掉自己 →
     * 即使还有空位也双双登录失败（已在真实 Redis 上复现同类缺陷）。
     *
     * @param loginId              账号ID
     * @param credentials          会话凭证
     * @param maxConcurrentLogins  最大并发登录数（&lt;=0 表示不限制）
     * @return true 已入列；false 已达并发上限，此时**未**入列
     */
    private boolean addToOnlineListIfLimitNotExceeded(Object loginId, String credentials, int maxConcurrentLogins) {
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            if (maxConcurrentLogins > 0 && this.countValidOnlineSessions(loginId) >= maxConcurrentLogins) {
                return false;
            }
            this.loginIdToCredentialsMap.computeIfAbsent(loginIdStr, k -> new CopyOnWriteArrayList<>()).add(credentials);
            return true;
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
