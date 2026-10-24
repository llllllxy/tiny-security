package org.tinycloud.security.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.session.timedcache.LocalTimeCache;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 单机内存会话仓储实现
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class SingleSessionRepository implements SessionRepository, DisposableBean {
    private static final Logger log = LoggerFactory.getLogger(SingleSessionRepository.class);

    /**
     * 维护会话核心内存缓存（线程安全）
     */
    private final LocalTimeCache timedCache = new LocalTimeCache(
            new ConcurrentHashMap<>(),
            new ConcurrentHashMap<>()
    );

    /**
     * key: loginId（转为String），value: 该账号的所有在线凭证列表
     */
    private final Map<String, List<String>> loginIdToCredentialsMap = new ConcurrentHashMap<>();

    /**
     * 保护 {@link #loginIdToCredentialsMap} 及其 list 变更的锁。
     * <p>list 变更（add/remove/就地清理/整体删除）统一在此锁内完成，
     * 避免并发 {@code add} 与 {@code put} 整体替换交错导致丢失更新。
     */
    private final Object onlineLock = new Object();

    /**
     * 构造单机内存会话仓储并启动过期清理线程。
     */
    public SingleSessionRepository() {
        this.timedCache.initRefreshThread();
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
            // 此时必须明确失败，绝不能静默覆盖掉另一个用户的会话。
            // （timeout 非法时 setObjectIfAbsent 同样不写入并返回 false；此时登录失败也是正确行为——
            //   宁可不发 token，也不能发出一个后端查不到的 token）
            boolean saved = this.timedCache.setObjectIfAbsent(
                    AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials(), subject, timeoutSeconds);
            if (!saved) {
                log.error("SingleSessionRepository save failed: credentials collision detected, or the timeout {} is invalid. The session was not created!", timeoutSeconds);
                return false;
            }
            // 先写会话、再原子占名额，顺序不能颠倒：若先占名额，并发的清理逻辑会因为凭证还不存在
            // 而把刚加入的凭证误判为"失效"并移除
            if (!this.addToOnlineListIfLimitNotExceeded(subject.getLoginId(), subject.getCredentials(), maxConcurrentLogins)) {
                // 并发竞争下没抢到名额：必须回滚刚写入的会话，否则会留下一个绕过并发上限的可用会话
                this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials());
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + maxConcurrentLogins + ") reached for the account; further logins are prohibited!");
            }
            return true;
        } catch (ConcurrentLoginOverLimitException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("SingleSessionRepository save failed, Exception：", e);
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
            return isCredentialValid(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
        } catch (Exception e) {
            log.error("SingleSessionRepository checkByCredentials failed, Exception：", e);
            return false;
        }
    }

    /**
     * 根据凭证读取登录主体。
     *
     * <p>返回**副本**：本仓储把对象引用存在内存里，若直接返回缓存实例，调用方修改它（如
     * {@code setLoginExpireTime(...)}）会污染缓存并在后续请求中生效，而 redis/jdbc 仓储每次
     * 反序列化出新对象、不受影响 —— 同一份代码在四种仓储下语义会不一致。
     */
    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String cacheKey = AuthConsts.AUTH_CREDENTIALS_KEY + credentials;
            if (!isCredentialValid(cacheKey)) {
                return null;
            }
            Object content = this.timedCache.getObject(cacheKey);
            return content == null ? null : ((LoginSubject) content).copy();
        } catch (Exception e) {
            log.error("SingleSessionRepository getSubject failed, Exception：", e);
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
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, subject, timeoutSeconds);
            return true;
        } catch (Exception e) {
            log.error("SingleSessionRepository refreshByCredentials failed, Exception：", e);
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
            this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return true;
        } catch (Exception e) {
            log.error("SingleSessionRepository deleteByCredentials failed, Exception：", e);
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
                    this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
                }
            }
            return true;
        } catch (Exception e) {
            log.error("SingleSessionRepository deleteByLoginId failed, Exception：", e);
            return false;
        }
    }

    /**
     * 统计指定账号有效在线会话数，并清理失效凭证索引。
     * <p>在 {@link #onlineLock} 锁内对 list 就地过滤（removeIf），
     * 不再用 {@code put} 整体替换引用，避免与并发 {@code add} 交错丢失更新。
     */
    @Override
    public int countValidOnlineSessions(Object loginId) {
        String loginIdStr = String.valueOf(loginId);
        synchronized (onlineLock) {
            List<String> credentialsList = this.loginIdToCredentialsMap.get(loginIdStr);
            if (credentialsList == null || credentialsList.isEmpty()) {
                return 0;
            }
            // 就地移除失效凭证，不替换 list 引用（并发 add 不会丢失）
            credentialsList.removeIf(cred -> !isCredentialValid(AuthConsts.AUTH_CREDENTIALS_KEY + cred));
            if (credentialsList.isEmpty()) {
                this.loginIdToCredentialsMap.remove(loginIdStr);
                return 0;
            }
            return credentialsList.size();
        }
    }

    /**
     * 获取指定账号下全部有效（未过期）会话凭证。
     * <p>在 {@link #onlineLock} 锁内先就地清理失效凭证，再返回列表副本，
     * 避免调用方持有内部 list 引用后与并发变更互相干扰。
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
            credentialsList.removeIf(cred -> !isCredentialValid(AuthConsts.AUTH_CREDENTIALS_KEY + cred));
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
     * <p>本仓储把"账号 → 凭证列表"的索引整个放在内存 Map 里，因此全局查询就是遍历它的 keySet ——
     * 纯内存操作，无需像 redis 仓储那样 SCAN key 空间。
     *
     * <p>逐个用 {@link #countValidOnlineSessions(Object)} 回查，而不是直接返回 keySet：
     * 索引里的凭证可能因缓存 TTL 到期或 {@code loginExpireTime} 过期而失效（内存索引不会自动清理，
     * 清理靠"该账号下次被访问时"惰性触发），直接返回会把已掉线的账号算作在线。
     * 这次回查顺带完成惰性清理。
     *
     * <p><b>多实例部署只能看到本实例</b>：本仓储是单机内存存储（{@code store-type=single}），
     * 每个 JVM 持有自己的一份会话。这里的"全量"指的是<b>当前这个实例</b>的全部在线账号，
     * 不是整个集群的。需要全局视图请用 {@code redis} 或 {@code jdbc} 存储。
     *
     * <p>实现细节：遍历的是 keySet 的<b>副本</b>——{@code countValidOnlineSessions} 在账号的
     * 凭证全部失效时会 {@code loginIdToCredentialsMap.remove(...)}，直接迭代 keySet 会触发
     * {@code ConcurrentModificationException}。
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
     * 判断指定缓存中的凭证是否有效（存在、未过期、且主体自身的 {@code loginExpireTime} 未过期）。
     *
     * <p><b>为什么两个有效期都要看（TCK 发现）</b>：本仓储的记录存活由缓存 TTL 决定，
     * 但会话是否过期还应以 `LoginSubject.loginExpireTime` 为准 —— 这也是 redis / jdbc / caffeine
     * 三个仓储的口径。此前这里只看缓存 TTL，于是"缓存 TTL 仍有效、但 loginExpireTime 已过期"的
     * 会话会被判定为**有效**，与其它三个仓储行为不一致（TCK 的
     * {@code expiredSessionShouldBeTreatedAsAbsent} 等用例直接抓到了这一点）。
     *
     * <p>两个条件必须同时满足：缓存 TTL 判断"记录是否还在"，{@code loginExpireTime} 判断
     * "会话是否已过期"。任一不满足即为无效。
     *
     * @param cacheKey 缓存 key
     * @return true-有效
     */
    private boolean isCredentialValid(String cacheKey) {
        long timeout = this.timedCache.getObjectTimeout(cacheKey);
        if (timeout <= 0 && timeout != LocalTimeCache.NEVER_EXPIRE) {
            return false;
        }
        Object content = this.timedCache.getObject(cacheKey);
        if (!(content instanceof LoginSubject subject)) {
            return false;
        }
        Long loginExpireTime = subject.getLoginExpireTime();
        // 缺 loginExpireTime 的主体按"已失效"处理，与内核（DefaultAuthenticationManager）及
        // caffeine 仓储的口径一致；NEVER_EXPIRE_TIME 已取消，这里不再有永不过期特例
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
     * 在 Spring 容器关闭时停止本地缓存清理线程，防止线程泄露。
     */
    @Override
    public void destroy() {
        this.timedCache.endRefreshThread();
    }
}
