package org.tinycloud.security.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.AuthException;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.tinycloud.security.util.JsonUtil;
import org.tinycloud.security.util.JwtUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    private ListOperations<String, String> listOps() {
        return redisTemplate.opsForList();
    }

    /**
     * 清理账号的无效在线凭证，返回有效凭证列表
     *
     * @param loginId 账号ID（与登录时传入的 loginId 一致）
     */
    private List<String> clearInvalidCredentials(Object loginId) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId.toString();
        // 获取该账号的所有在线凭证
        List<String> credentialsList = listOps().range(onlineKey, 0, -1);
        if (credentialsList == null || credentialsList.isEmpty()) {
            redisTemplate.delete(onlineKey);
            return new ArrayList<>();
        }
        // 标记需要删除的无效凭证
        List<String> invalidCredentials = credentialsList.stream()
                .filter(cred -> !redisTemplate.hasKey(AuthConsts.AUTH_CREDENTIALS_KEY + cred))
                .toList();
        if (!invalidCredentials.isEmpty()) {
            // 批量删除无效凭证（一次Redis操作，而非逐个删除）
            for (String invalidCred : invalidCredentials) {
                listOps().remove(onlineKey, 1, invalidCred);
            }
            // 重新获取清理后的有效列表（确保数据准确）
            credentialsList = listOps().range(onlineKey, 0, -1);
        }

        // 兜底：若列表为空，删除Key
        if (credentialsList == null || credentialsList.isEmpty()) {
            redisTemplate.delete(onlineKey);
            return new ArrayList<>();
        }
        return credentialsList;
    }


    /**
     * 校验当前在线人数是否超上限
     *
     * @param loginId 账号ID
     * @return true：未超上限；false：已超上限
     */
    private boolean checkMaxLoginLimit(Object loginId) {
        int maxLogin = GlobalConfigUtils.getGlobalConfig().getMaxLogin();
        if (maxLogin <= 0) {
            return true; // 最大人数为0表示不限制
        }

        // 清理无效凭证后，获取有效在线数
        List<String> validCredentials = clearInvalidCredentials(loginId);
        int currentOnlineCount = validCredentials == null ? 0 : validCredentials.size();

        log.info("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxLogin);
        return currentOnlineCount < maxLogin;
    }

    /**
     * 添加凭证到账号的在线列表
     *
     * @param loginId     账号ID
     * @param credentials 会话凭证
     */
    private void addToOnlineList(Object loginId, String credentials) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId.toString();
        listOps().rightPush(onlineKey, credentials);
        log.info("账号{}新增在线凭证：{}，当前在线数：{}", loginId, credentials, listOps().size(onlineKey));

        // 可选：添加后再次校验人数，若超量则回滚（降低超量影响）
        int maxLogin = GlobalConfigUtils.getGlobalConfig().getMaxLogin();
        if (maxLogin > 0) {
            Long size = listOps().size(onlineKey);
            if (size != null && size > maxLogin) {
                // 回滚：删除刚添加的凭证（仅保留maxLogin个）
                listOps().remove(onlineKey, 1, credentials);
                log.warn("账号{}并发登录超量，回滚新增凭证：{}", loginId, credentials);
                throw new AuthException("Maximum concurrent logins ({" + maxLogin + "}) reached for the account; further logins are prohibited!");
            }
        }
    }

    /**
     * 从账号的在线列表中移除凭证（退出登录时调用）
     *
     * @param loginId     账号ID
     * @param credentials 会话凭证
     */
    private void removeFromOnlineList(Object loginId, String credentials) {
        String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId.toString();
        // 删除列表中1个匹配的凭证（避免重复删除）
        long removeCount = listOps().remove(onlineKey, 1, credentials);
        if (removeCount > 0) {
            log.info("账号{}移除在线凭证：{}", loginId, credentials);
            // 若列表为空，删除Key
            Long size = listOps().size(onlineKey);
            if (size != null && size == 0) {
                redisTemplate.delete(onlineKey);
                log.info("账号{}所有会话已退出，删除在线列表Key", loginId);
            }
        }
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
            return this.redisTemplate.expire(AuthConsts.AUTH_CREDENTIALS_KEY + credentials, GlobalConfigUtils.getGlobalConfig().getTimeout(), TimeUnit.SECONDS);
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
            return this.redisTemplate.hasKey(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
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

    @Override
    public String login(Object loginId, Map<String, Object> extraInfo) {
        if (loginId == null) {
            throw new AuthException("loginId can not be null!");
        }
        try {
            // 1. 校验在线人数是否超上限（无锁，依赖后续回滚兜底）
            boolean canLogin = checkMaxLoginLimit(loginId);
            if (!canLogin) {
                int maxLogin = GlobalConfigUtils.getGlobalConfig().getMaxLogin();
                throw new AuthException("Maximum concurrent logins ({" + maxLogin + "}) reached for the account; further logins are prohibited!");
            }
            // 2. 调用父类登录逻辑（创建token、设置Cookie）
            return super.login(loginId, extraInfo);
        } catch (AuthException e) {
            // 直接抛出业务异常（如超量、回滚失败）
            throw e;
        } catch (Exception e) {
            log.error("登录异常，loginId：{}", loginId, e);
            throw new AuthException("Login exception occurred. Please try again!", e);
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
            // 1. 生成唯一会话凭证（credentials）
            String credentials = CredentialsGenUtil.generate(GlobalConfigUtils.getGlobalConfig().getCredentialsStyle());
            Map<String, String> payload = new HashMap<>();
            payload.put("credentials", credentials);
            // 2. 生成JWT Token（包含credentials）
            String jwtToken = JwtUtil.sign(GlobalConfigUtils.getGlobalConfig().getJwtSecret(), GlobalConfigUtils.getGlobalConfig().getJwtSubject(), payload);
            // 3. 构建登录用户信息（LoginSubject），存储到Redis
            LoginSubject subject = new LoginSubject();
            subject.setExtraInfo(extraInfo);
            subject.setLoginId(loginId);
            long currentTime = System.currentTimeMillis();
            subject.setLoginTime(currentTime);
            subject.setLoginExpireTime(currentTime + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000L);
            this.redisTemplate.opsForValue().set(AuthConsts.AUTH_CREDENTIALS_KEY + credentials,
                    JsonUtil.writeValueAsString(subject), GlobalConfigUtils.getGlobalConfig().getTimeout(), TimeUnit.SECONDS);
            // 4.将凭证添加到账号的在线列表
            this.addToOnlineList(loginId, credentials);
            return AuthConsts.JWT_TOKEN_PREFIX + jwtToken;
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("RedisAuthProvider createAuth failed, Exception：", e);
            throw new AuthException("Failed to create session. Please retry!", e);
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
            LoginSubject subject = this.getSubject(credentials);
            if (subject != null) {
                this.removeFromOnlineList(subject.getLoginId(), credentials);
            }
            return this.redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
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
            LoginSubject subject = this.getSubject(credentials);
            if (subject != null) {
                this.removeFromOnlineList(subject.getLoginId(), credentials);
            }
            return this.redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + credentials);
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
            String onlineKey = AuthConsts.ONLINE_CREDENTIALS_KEY_PREFIX + loginId.toString();
            List<String> credentialsList = listOps().range(onlineKey, 0, -1);
            if (credentialsList == null || credentialsList.isEmpty()) {
                log.info("删除账号会话失败：无在线凭证，loginId：{}", loginId);
                return false;
            }
            // 1. 批量删除所有凭证
            for (String cred : credentialsList) {
                redisTemplate.delete(AuthConsts.AUTH_CREDENTIALS_KEY + cred);
            }
            // 2. 删除在线列表Key
            this.redisTemplate.delete(onlineKey);
            log.info("删除账号所有会话成功，loginId：{}，共删除{}个凭证", loginId, credentialsList.size());
            return true;
        } catch (Exception e) {
            log.error("RedisAuthProvider deleteByLoginId failed, Exception：", e);
            return false;
        }
    }
}
