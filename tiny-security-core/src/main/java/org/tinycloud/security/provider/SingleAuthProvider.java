package org.tinycloud.security.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.provider.timedcache.LocalMapContainerByConcurrentHashMap;
import org.tinycloud.security.provider.timedcache.LocalTimeCache;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.tinycloud.security.util.JwtUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * 操作token和会话的接口（通过单机内存Map实现，系统重启后数据会丢失）
 * 部分代码实现参考自 <a href="https://gitee.com/dromara/sa-token/blob/dev/sa-token-core/src/main/java/cn/dev33/satoken/dao/SaTokenDaoDefaultImpl.java">SaTokenDaoDefaultImpl.java</a>
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class SingleAuthProvider extends AbstractAuthProvider implements AuthProvider {
    private final static Logger log = LoggerFactory.getLogger(SingleAuthProvider.class);

    /**
     * 维护token和会话的核心内存缓存（线程安全）
     */
    public LocalTimeCache timedCache = new LocalTimeCache(new LocalMapContainerByConcurrentHashMap<>(), new LocalMapContainerByConcurrentHashMap<>());

    /**
     * key: loginId（转为String），value: 该账号的所有在线凭证列表。使用 ConcurrentHashMap 保证多线程安全（单机环境下足够）
     */
    private final Map<String, List<String>> loginIdToCredentialsMap = new ConcurrentHashMap<>();


    /**
     * 构造函数
     */
    public SingleAuthProvider() {
        // 同时初始化定时任务
        this.timedCache.initRefreshThread();
    }


    /**
     * 统计账号的有效在线会话数（过滤已过期凭证）
     *
     * @param loginId 账号ID
     * @return 有效会话数
     */
    private int countValidOnlineSessions(Object loginId) {
        String loginIdStr = String.valueOf(loginId);
        // 1. 获取该账号的所有凭证列表（无则返回0）
        List<String> credentialsList = this.loginIdToCredentialsMap.getOrDefault(loginIdStr, Collections.emptyList());
        if (credentialsList.isEmpty()) {
            return 0;
        }
        // 2. 过滤已过期的凭证（校验凭证是否在 timedCache 中有效）
        List<String> validCredentials = credentialsList.stream()
                .filter(cred -> {
                    String cacheKey = AuthConsts.AUTH_CREDENTIALS_KEY + cred;
                    long timeout = this.timedCache.getObjectTimeout(cacheKey);
                    return timeout > 0; // 超时时间>0 表示凭证有效
                })
                .collect(Collectors.toList());
        // 3. 同步更新内存Map（移除已过期的凭证，避免Map无限膨胀）
        if (validCredentials.size() != credentialsList.size()) {
            if (validCredentials.isEmpty()) {
                this.loginIdToCredentialsMap.remove(loginIdStr); // 无有效凭证，删除key
            } else {
                this.loginIdToCredentialsMap.put(loginIdStr, validCredentials); // 更新为有效列表
            }
        }
        return validCredentials.size();
    }

    /**
     * 校验在线人数是否超上限
     *
     * @param loginId 账号ID
     * @return true：未超上限；false：已超上限
     */
    private boolean checkMaxLoginLimit(Object loginId) {
        int maxLogin = GlobalConfigUtils.getGlobalConfig().getMaxConcurrentLogins();
        if (maxLogin <= 0) {
            return true; // 为0或者负数表示不限制
        }
        int currentOnlineCount = countValidOnlineSessions(loginId);
        log.info("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxLogin);
        return currentOnlineCount < maxLogin;
    }

    /**
     * 将新凭证添加到账号的在线列表
     *
     * @param loginId     账号ID
     * @param credentials 新生成的凭证
     */
    private void addToOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        // ConcurrentHashMap 确保多线程安全，computeIfAbsent 不存在则创建新列表
        loginIdToCredentialsMap.computeIfAbsent(loginIdStr, k -> new CopyOnWriteArrayList<>()).add(credentials);
        log.info("账号{}新增在线凭证：{}，当前在线数：{}", loginId, credentials, loginIdToCredentialsMap.get(loginIdStr).size());
    }

    /**
     * 从账号的在线列表中移除凭证（退出登录时调用）
     *
     * @param loginId     账号ID
     * @param credentials 要删除的凭证
     */
    private void removeFromOnlineList(Object loginId, String credentials) {
        String loginIdStr = String.valueOf(loginId);
        List<String> credentialsList = loginIdToCredentialsMap.get(loginIdStr);
        if (credentialsList == null || credentialsList.isEmpty()) {
            return;
        }

        // 移除凭证（CopyOnWriteArrayList 支持并发删除）
        boolean removed = credentialsList.remove(credentials);
        if (removed) {
            log.info("账号{}移除在线凭证：{}", loginId, credentials);
            // 无有效凭证时，删除Map中的key，避免内存泄漏
            if (credentialsList.isEmpty()) {
                loginIdToCredentialsMap.remove(loginIdStr);
                log.info("账号{}所有会话已退出，删除在线列表映射", loginId);
            }
        }
    }


    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, (subject), GlobalConfigUtils.getGlobalConfig().getTimeout());
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - refreshCredentials - failed，Exception：", e);
            return false;
        }
    }

    /**
     * 检查凭证是否失效
     *
     * @param credentials 凭证
     * @return true有效，false已失效
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            long timeout = this.timedCache.getObjectTimeout(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return timeout > 0;
        } catch (Exception e) {
            log.error("SingleAuthProvider - checkCredentials - failed，Exception：", e);
            return false;
        }
    }

    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            long timeout = this.timedCache.getObjectTimeout(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            if (timeout <= 0) {
                return null;
            } else {
                Object content = this.timedCache.getObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
                return content == null ? null : (LoginSubject) content;
            }
        } catch (Exception e) {
            log.error("SingleAuthProvider - getSubject - failed，Exception：", e);
            return null;
        }
    }

    /**
     * 创建会话，并返回一个token
     *
     * @param loginId   会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @param extraInfo 额外的扩展信息，更灵活
     * @return token令牌
     * @throws ConcurrentLoginOverLimitException 并发登录超过上限异常
     * @throws TinySecurityException             其他安全异常
     */
    @Override
    public String createAuth(Object loginId, Map<String, Object> extraInfo) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        Assert.isTrue(loginId instanceof Number || loginId instanceof String, "loginId must be of type Number (Long, Integer, etc.) or String, but got: " + loginId.getClass().getName());
        try {
            // 1. 校验在线人数是否超上限（核心新增逻辑）
            boolean canLogin = this.checkMaxLoginLimit(loginId);
            if (!canLogin) {
                throw new ConcurrentLoginOverLimitException("Maximum concurrent logins (" + GlobalConfigUtils.getGlobalConfig().getMaxConcurrentLogins() + ") reached for the account; further logins are prohibited!");
            }

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
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, subject, GlobalConfigUtils.getGlobalConfig().getTimeout());

            // 新增：将凭证添加到在线列表
            this.addToOnlineList(loginId, credentials);

            return AuthConsts.JWT_TOKEN_PREFIX + jwtToken;
        } catch (ConcurrentLoginOverLimitException e) {
            throw e;
        } catch (Exception e) {
            log.error("SingleAuthProvider createAuth failed, Exception：", e);
            throw new TinySecurityException("Failed to create auth. Please retry!", e);
        }
    }

    /**
     * 删除会话根据token
     *
     * @param token 令牌
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByToken(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String credentials = this.getCredentialsByToken(token);
            LoginSubject subject = this.getSubject(credentials);
            if (subject != null) {
                this.removeFromOnlineList(subject.getLoginId(), credentials);
            }
            this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - deleteByToken - failed，Exception：", e);
            return false;
        }
    }

    /**
     * 删除会话根据credentials
     *
     * @param credentials 凭证
     * @return true成功，false失败
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
            log.error("SingleAuthProvider - deleteByCredentials - failed，Exception：", e);
            return false;
        }
    }

    /**
     * 通过loginId删除token
     *
     * @param loginId 用户id
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        try {
            String loginIdStr = String.valueOf(loginId);
            // 1. 从在线列表中获取该账号的所有凭证
            List<String> credentialsList = this.loginIdToCredentialsMap.getOrDefault(loginIdStr, Collections.emptyList());
            // 2. 批量删除 timedCache 中的凭证
            for (String cred : credentialsList) {
                this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
            }
            // 3. 删除在线列表映射
            this.loginIdToCredentialsMap.remove(loginIdStr);
            log.info("账号{}所有会话已删除，共删除{}个凭证", loginId, credentialsList.size());
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - deleteByLoginId - failed，Exception：", e);
            return false;
        }
    }
}