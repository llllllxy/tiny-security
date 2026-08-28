package org.tinycloud.security.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.util.Assert;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.session.timedcache.LocalMapContainerByConcurrentHashMap;
import org.tinycloud.security.session.timedcache.LocalTimeCache;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

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
            new LocalMapContainerByConcurrentHashMap<>(),
            new LocalMapContainerByConcurrentHashMap<>()
    );

    /**
     * key: loginId（转为String），value: 该账号的所有在线凭证列表
     */
    private final Map<String, List<String>> loginIdToCredentialsMap = new ConcurrentHashMap<>();

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
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + subject.getCredentials(), subject, timeoutSeconds);
            this.addToOnlineList(subject.getLoginId(), subject.getCredentials());
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
            return content == null ? null : (LoginSubject) content;
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
            List<String> credentialsList = this.loginIdToCredentialsMap.getOrDefault(loginIdStr, Collections.emptyList());
            for (String cred : credentialsList) {
                this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
            }
            this.loginIdToCredentialsMap.remove(loginIdStr);
            return true;
        } catch (Exception e) {
            log.error("SingleSessionRepository deleteByLoginId failed, Exception：", e);
            return false;
        }
    }

    /**
     * 统计指定账号有效在线会话数，并清理失效凭证索引。
     */
    @Override
    public int countValidOnlineSessions(Object loginId) {
        String loginIdStr = String.valueOf(loginId);
        List<String> credentialsList = this.loginIdToCredentialsMap.getOrDefault(loginIdStr, Collections.emptyList());
        if (credentialsList.isEmpty()) {
            return 0;
        }
        List<String> validCredentials = credentialsList.stream()
                .filter(cred -> isCredentialValid(AuthConsts.AUTH_CREDENTIALS_KEY + cred))
                .collect(Collectors.toList());
        if (validCredentials.size() != credentialsList.size()) {
            if (validCredentials.isEmpty()) {
                this.loginIdToCredentialsMap.remove(loginIdStr);
            } else {
                this.loginIdToCredentialsMap.put(loginIdStr, validCredentials);
            }
        }
        return validCredentials.size();
    }

    /**
     * 判断指定缓存中的凭证是否有效（存在且未过期）。
     * 永不过期（剩余存活时间为 NEVER_EXPIRE）的凭证视为有效。
     */
    private boolean isCredentialValid(String cacheKey) {
        long timeout = this.timedCache.getObjectTimeout(cacheKey);
        return timeout > 0 || timeout == LocalTimeCache.NEVER_EXPIRE;
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
    private void addToOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        loginIdToCredentialsMap.computeIfAbsent(loginIdStr, k -> new CopyOnWriteArrayList<>()).add(credentials);
    }

    /**
     * 从账号在线列表中移除凭证。
     */
    private void removeFromOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        List<String> credentialsList = loginIdToCredentialsMap.get(loginIdStr);
        if (credentialsList == null || credentialsList.isEmpty()) {
            return;
        }
        boolean removed = credentialsList.remove(credentials);
        if (removed && credentialsList.isEmpty()) {
            loginIdToCredentialsMap.remove(loginIdStr);
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
