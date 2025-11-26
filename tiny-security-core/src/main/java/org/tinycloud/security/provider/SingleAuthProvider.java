package org.tinycloud.security.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.provider.timedcache.LocalMapContainerByConcurrentHashMap;
import org.tinycloud.security.provider.timedcache.LocalTimeCache;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.tinycloud.security.util.JwtUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * 操作token和会话的接口（通过单机内存Map实现，系统重启后数据会丢失）
 * 部分代码实现参考自 https://gitee.com/dromara/sa-token/blob/dev/sa-token-core/src/main/java/cn/dev33/satoken/dao/SaTokenDaoDefaultImpl.java
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class SingleAuthProvider extends AbstractAuthProvider implements AuthProvider {
    private final static Logger log = LoggerFactory.getLogger(SingleAuthProvider.class);

    public LocalTimeCache timedCache = new LocalTimeCache(new LocalMapContainerByConcurrentHashMap<>(), new LocalMapContainerByConcurrentHashMap<>());


    /**
     * 构造函数
     */
    public SingleAuthProvider() {
        // 同时初始化定时任务
        this.timedCache.initRefreshThread();
    }

    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, (subject), GlobalConfigUtils.getGlobalConfig().getTimeout());
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - refreshCredentials - failed，Exception：{e}", e);
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
            log.error("SingleAuthProvider - checkCredentials - failed，Exception：{e}", e);
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
            log.error("SingleAuthProvider - getSubject - failed，Exception：{e}", e);
            return null;
        }
    }

    /**
     * 创建一个新的token
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return token
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
            this.timedCache.setObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, subject, GlobalConfigUtils.getGlobalConfig().getTimeout());
            return AuthConsts.JWT_TOKEN_PREFIX + jwtToken;
        } catch (Exception e) {
            log.error("SingleAuthProvider - createToken - failed，Exception：{e}", e);
            return null;
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
            this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - deleteByToken - failed，Exception：{e}", e);
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
            this.timedCache.deleteObject(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - deleteByCredentials - failed，Exception：{e}", e);
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
            for (String key : this.timedCache.expireMapKeySet()) {
                LoginSubject subject = (LoginSubject) this.timedCache.getObject(key);
                if (subject != null && loginId.equals(subject.getLoginId())) {
                    this.timedCache.deleteObject(key);
                }
            }
            return true;
        } catch (Exception e) {
            log.error("SingleAuthProvider - deleteByLoginId - failed，Exception：{e}", e);
            return false;
        }
    }
}