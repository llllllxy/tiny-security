package org.tinycloud.security.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.util.JsonUtil;

import java.util.ArrayList;
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

    /**
     * 「判断并发上限 + 加入在线列表」的原子脚本（P1-7）。
     *
     * <p>这两步必须原子完成，否则并发登录会得到两种错误结果：
     * <ul>
     *     <li>都通过上限判断后各自入列 → 实际在线数突破上限（静默超额）；</li>
     *     <li>都入列后再各自发现超额、各自摘掉自己 → 即使还有空位也双双登录失败
     *         （已在真实 Redis 上复现：上限为 1 时 4 个并发登录全部被拒）。</li>
     * </ul>
     *
     * <p>脚本只操作 KEYS[1] 一个键。Redis Cluster 要求脚本内访问的所有键同属一个 slot，
     * 而"凭证 key"与"在线列表 key"天然不同 slot，因此失效凭证的清理仍留在 Java 侧完成。
     *
     * <p>参数：KEYS[1] = 在线列表 key；ARGV[1] = 凭证；ARGV[2] = 并发上限（&lt;=0 表示不限制）；
     * ARGV[3] = 列表 TTL 秒数（&lt;=0 表示不设置 TTL）。返回 1 = 已入列，0 = 已达上限、未入列。
     */
    private static final RedisScript<Long> ADD_TO_ONLINE_LIST_SCRIPT = RedisScript.of(
            "if tonumber(ARGV[2]) > 0 and redis.call('LLEN', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end\n"
                    + "redis.call('RPUSH', KEYS[1], ARGV[1])\n"
                    + "if tonumber(ARGV[3]) > 0 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3])) end\n"
                    + "return 1\n",
            Long.class);

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
            // 无论是否启用并发限制，登录时都清理该账号在线列表中的失效凭证，否则其随登录次数无限累积（内存泄漏）
            this.countValidOnlineSessions(subject.getLoginId());
            // 凭证是随机生成的会话唯一钥匙，理论上不会重复。一旦重复，说明随机源异常或有人在构造会话固定攻击，
            // 此时必须明确失败，绝不能静默覆盖掉另一个用户的会话
            String sessionKey = AuthConsts.AUTH_CREDENTIALS_KEY + credentials;
            Boolean absent = this.redisTemplate.opsForValue().setIfAbsent(
                    sessionKey,
                    JsonUtil.writeValueAsString(subject),
                    timeoutSeconds,
                    TimeUnit.SECONDS
            );
            if (!Boolean.TRUE.equals(absent)) {
                log.error("RedisSessionRepository save failed: credentials collision detected, the generated token already exists!");
                return false;
            }
            // 先写会话、再原子占名额，顺序不能颠倒：若先占名额，并发的清理逻辑会因为凭证 key 尚未写入
            // 而把刚入列的凭证误判为"失效"并移除
            boolean added;
            try {
                added = this.addToOnlineListIfLimitNotExceeded(subject.getLoginId(), credentials, maxConcurrentLogins, timeoutSeconds);
            } catch (Exception e) {
                // 占名额这一步自身失败（如 Redis 异常）：同样必须回滚会话，
                // 否则会留下一个不在在线列表里、却可以正常使用的会话（绕过并发上限）
                this.redisTemplate.delete(sessionKey);
                throw e;
            }
            if (!added) {
                // 并发竞争下没抢到名额：必须回滚刚写入的会话，否则会留下一个绕过并发上限的可用会话
                this.redisTemplate.delete(sessionKey);
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + maxConcurrentLogins + ") reached for the account; further logins are prohibited!");
            }
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
     *
     * <p><b>为什么不能只看 key 是否存在（TCK 发现）</b>：key 是否存在由 Redis TTL 决定，
     * 但会话是否过期应以 {@code LoginSubject.loginExpireTime} 为准 —— 这是 caffeine / jdbc
     * 两个仓储的口径。此前这里只做 {@code hasKey}，于是"key 尚未到期、但 loginExpireTime
     * 已过期"的会话会被判定为**有效**，与其它仓储不一致（TCK 的
     * {@code expiredSessionShouldBeTreatedAsAbsent} 等用例直接抓到了）。
     *
     * <p>与 {@code single} 仓储同源：两处都曾漏掉 {@code loginExpireTime} 判定。
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            return this.hasValidSubject(credentials);
        } catch (Exception e) {
            log.error("RedisSessionRepository checkByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证读取登录主体。
     *
     * <p>与 {@link #checkByCredentials(String)} 口径一致：{@code loginExpireTime} 已过期的主体
     * 视为读不到（返回 {@code null}），而不是把过期主体交给上层。
     */
    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            if (!this.hasValidSubject(credentials)) {
                return null;
            }
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
            String sessionKey = AuthConsts.AUTH_CREDENTIALS_KEY + credentials;
            this.redisTemplate.opsForValue().set(
                    sessionKey,
                    JsonUtil.writeValueAsString(subject),
                    timeoutSeconds,
                    TimeUnit.SECONDS
            );
            // 会话滚动续期（常在线账号可能远超单次超时）时同步刷新在线列表 TTL，
            // 否则在线列表会先于会话过期，导致常在线账号被误判为离线、踢人/计数失效。
            // timeout<=0 不设置 TTL（timeout 已由 AuthProvider 装配期保证为正数，此处为防御性判断）
            if (subject != null && subject.getLoginId() != null && timeoutSeconds > 0) {
                this.redisTemplate.expire(
                        AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + subject.getLoginId(),
                        timeoutSeconds * 2L,
                        TimeUnit.SECONDS
                );
            }
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
            if (credentialsList != null) {
                for (String cred : credentialsList) {
                    redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
                }
            }
            this.redisTemplate.delete(onlineKey);
            // 幂等语义：无论是否有会话被删除，只要操作正常完成即视为成功
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
     * 获取指定账号下全部有效会话凭证。
     * <p>复用 {@link #clearInvalidCredentials(Object)}：它会在返回有效凭证前
     * 先把在线列表中的失效凭证清理掉（Redis 会话 key 过期后列表残留）。
     */
    @Override
    public List<String> getCredentialsByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        try {
            List<String> validCredentials = this.clearInvalidCredentials(loginId);
            return new ArrayList<>(validCredentials);
        } catch (Exception e) {
            log.error("RedisSessionRepository getCredentialsByLoginId failed, Exception：", e);
            return new ArrayList<>();
        }
    }

    /**
     * 清理在线列表中的失效凭证并返回有效凭证。
     *
     * <p>失效判定与 {@link #checkByCredentials(String)} 口径一致：不仅要看 key 是否存在
     * （存储 TTL），还要看主体的 {@code loginExpireTime} 是否已过期 —— 否则"key 尚未到期、
     * 但会话已过期"的凭证会被当成有效，导致在线数虚高（TCK 的
     * {@code countValidOnlineSessionsShouldCountOnlyValidOnes} 抓到过这一点）。
     */
    private List<String> clearInvalidCredentials(Object loginId) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
        List<String> credentialsList = this.redisTemplate.opsForList().range(onlineKey, 0, -1);
        if (credentialsList == null || credentialsList.isEmpty()) {
            this.redisTemplate.delete(onlineKey);
            return new ArrayList<>();
        }
        List<String> invalidCredentials = credentialsList.stream()
                .filter(cred -> !this.hasValidSubject(cred))
                .collect(Collectors.toList());
        if (!invalidCredentials.isEmpty()) {
            for (String invalidCred : invalidCredentials) {
                this.redisTemplate.opsForList().remove(onlineKey, 1, invalidCred);
            }
            credentialsList = this.redisTemplate.opsForList().range(onlineKey, 0, -1);
        }
        if (credentialsList == null || credentialsList.isEmpty()) {
            this.redisTemplate.delete(onlineKey);
            return new ArrayList<>();
        }
        return credentialsList;
    }

    /**
     * 凭证是否对应一个"存储层存在且会话未过期"的主体。
     *
     * <p>抽出来是为了让 {@link #checkByCredentials(String)}、{@link #getSubject(String)} 与
     * 在线列表清理三处共用同一判定口径，避免再次出现"某处只看 key、某处看 loginExpireTime"
     * 的不一致。
     *
     * @param credentials 会话凭证
     * @return true-有效
     */
    private boolean hasValidSubject(String credentials) {
        String content = this.redisTemplate.opsForValue().get(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
        if (content == null) {
            return false;
        }
        LoginSubject subject = JsonUtil.readValue(content, LoginSubject.class);
        Long loginExpireTime = subject == null ? null : subject.getLoginExpireTime();
        return loginExpireTime != null && loginExpireTime > System.currentTimeMillis();
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
     * 原子地判断并发上限并把凭证加入账号在线列表，同时给列表设置独立的过期时间。
     *
     * @param loginId              账号ID
     * @param credentials          会话凭证
     * @param maxConcurrentLogins  最大并发登录数（&lt;=0 表示不限制）
     * @param timeoutSeconds       会话超时时间（秒）
     * @return true 已入列；false 已达并发上限，此时**未**入列
     */
    private boolean addToOnlineListIfLimitNotExceeded(Object loginId, String credentials, int maxConcurrentLogins, int timeoutSeconds) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId;
        // 在线列表与凭证 key 一样必须有 TTL，否则默认配置（未开启并发限制时清理逻辑不触发）
        // 失效凭证会在列表中永久残留，随登录次数无限累积（内存泄漏）。
        // 仅在会话超时为正数时设置 TTL（timeout 已由 AuthProvider 装配期保证为正数，此处为防御性判断）
        long listTimeoutSeconds = timeoutSeconds > 0 ? timeoutSeconds * 2L : 0L;
        Long added = this.redisTemplate.execute(ADD_TO_ONLINE_LIST_SCRIPT,
                List.of(onlineKey),
                credentials,
                String.valueOf(maxConcurrentLogins),
                String.valueOf(listTimeoutSeconds));
        return added != null && added > 0;
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
