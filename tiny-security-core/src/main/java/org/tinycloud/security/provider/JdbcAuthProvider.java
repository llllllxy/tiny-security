package org.tinycloud.security.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.AuthException;
import org.tinycloud.security.util.CredentialsGenUtil;
import org.tinycloud.security.util.JsonUtil;
import org.tinycloud.security.util.JwtUtil;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 操作token和会话的接口（通过jdbc实现）
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class JdbcAuthProvider extends AbstractAuthProvider implements AuthProvider {
    private final static Logger log = LoggerFactory.getLogger(JdbcAuthProvider.class);

    private final JdbcTemplate jdbcTemplate;

    public JdbcAuthProvider(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        // 同时初始化定时任务
        this.initCleanThread();
    }


    /**
     * 统计当前账号的有效在线会话数（未过期）
     *
     * @param loginId 账号ID
     * @return 有效会话数
     */
    private int countValidOnlineSessions(Object loginId) {
        // SQL：统计 login_id 匹配且未过期的记录数
        String sql = "SELECT COUNT(1) FROM " + GlobalConfigUtils.getGlobalConfig().getTableName() + " WHERE login_id = ? AND credentials_expire_time > ?";
        try {
            Long count = jdbcTemplate.queryForObject(sql, Long.class, loginId, System.currentTimeMillis());
            return count == null ? 0 : count.intValue();
        } catch (Exception e) {
            log.error("统计账号{}有效在线会话数失败", loginId, e);
            return 0; // 异常时默认返回0（避免影响登录，实际业务可调整为抛出异常）
        }
    }

    /**
     * 校验当前在线人数是否超上限
     *
     * @param loginId 账号ID
     * @return true：未超上限；false：已超上限
     */
    private boolean checkMaxLoginLimit(Object loginId) {
        int maxLogin = GlobalConfigUtils.getGlobalConfig().getMaxConcurrentLogins();
        if (maxLogin <= 0) {
            return true; // 为0或者负数表示不限制
        }

        // 统计有效会话数（自动过滤过期会话，无需额外清理）
        int currentOnlineCount = countValidOnlineSessions(loginId);
        log.info("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxLogin);
        return currentOnlineCount < maxLogin;
    }


    @Override
    public boolean refreshByCredentials(String credentials, LoginSubject subject) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String sql = "UPDATE " + GlobalConfigUtils.getGlobalConfig().getTableName() + " SET credentials_expire_time = ?, login_subject = ? WHERE credentials = ?";
            int num = jdbcTemplate.update(sql, subject.getLoginExpireTime(), JsonUtil.writeValueAsString(subject), credentials);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider refreshByCredentials failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 检查token是否失效
     *
     * @param credentials 令牌
     * @return true未失效，false已失效
     */
    @Override
    public boolean checkByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String sql = "SELECT credentials_expire_time FROM " + GlobalConfigUtils.getGlobalConfig().getTableName()
                    + " WHERE credentials = ? AND credentials_expire_time > ?";
            List<Map<String, Object>> resultList = this.jdbcTemplate.queryForList(sql, credentials, System.currentTimeMillis());
            return !resultList.isEmpty();
        } catch (Exception e) {
            log.error("JdbcAuthProvider checkByCredentials failed, Exception: {e}", e);
            return false;
        }
    }

    @Override
    public LoginSubject getSubject(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty!");
        try {
            String sql = "SELECT login_subject FROM " + GlobalConfigUtils.getGlobalConfig().getTableName()
                    + " WHERE credentials = ? AND credentials_expire_time > ?";
            List<Map<String, Object>> resultList = this.jdbcTemplate.queryForList(sql, credentials, System.currentTimeMillis());
            if (!resultList.isEmpty()) {
                String content = resultList.get(0).get("login_subject").toString();
                return JsonUtil.readValue(content, LoginSubject.class);
            } else {
                return null;
            }
        } catch (Exception e) {
            log.error("JdbcAuthProvider getSubject failed, Exception：{e}", e);
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
            // 1. 校验在线人数是否超上限
            boolean canLogin = this.checkMaxLoginLimit(loginId);
            if (!canLogin) {
                throw new AuthException("Maximum concurrent logins ({" + GlobalConfigUtils.getGlobalConfig().getMaxConcurrentLogins() + "}) " +
                        "reached for the account; further logins are prohibited!");
            }
            // 2. 生成唯一会话凭证（credentials）
            String credentials = CredentialsGenUtil.generate(GlobalConfigUtils.getGlobalConfig().getCredentialsStyle());
            Map<String, String> payload = new HashMap<>();
            payload.put("credentials", credentials);
            // 3. 生成JWT Token（包含credentials）
            String jwtToken = JwtUtil.sign(GlobalConfigUtils.getGlobalConfig().getJwtSecret(), GlobalConfigUtils.getGlobalConfig().getJwtSubject(), payload);
            // 4. 构建登录用户信息（LoginSubject），存储到Database
            LoginSubject subject = new LoginSubject();
            subject.setExtraInfo(extraInfo);
            subject.setLoginId(loginId);
            long currentTime = System.currentTimeMillis();
            subject.setLoginTime(currentTime);
            long loginExpireTime = currentTime + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000L;
            subject.setLoginExpireTime(loginExpireTime);
            String sql = "INSERT INTO " + GlobalConfigUtils.getGlobalConfig().getTableName() + " (credentials,login_id,login_subject,credentials_expire_time) VALUES (?,?,?,?)";
            int num = jdbcTemplate.update(sql, credentials, String.valueOf(loginId), JsonUtil.writeValueAsString(subject), subject.getLoginExpireTime());
            return num > 0 ? AuthConsts.JWT_TOKEN_PREFIX + jwtToken : null;
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            log.error("JdbcAuthProvider createAuth failed, Exception：", e);
            throw new AuthException("Failed to create auth. Please retry!", e);
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
        Assert.hasText(token, "The token cannot be empty！");
        try {
            String credentials = this.getCredentialsByToken(token);
            String sql = "DELETE FROM " + GlobalConfigUtils.getGlobalConfig().getTableName() + " WHERE credentials = ?";
            int num = jdbcTemplate.update(sql, credentials);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider deleteByToken failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 删除会话根据凭证
     *
     * @param credentials 凭证
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByCredentials(String credentials) {
        Assert.hasText(credentials, "The credentials cannot be empty！");
        try {
            String sql = "DELETE FROM " + GlobalConfigUtils.getGlobalConfig().getTableName() + " WHERE credentials = ?";
            int num = jdbcTemplate.update(sql, credentials);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider deleteByCredentials failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 通过loginId删除token
     *
     * @param loginId 会话id
     * @return true成功，false失败
     */
    @Override
    public boolean deleteByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null！");
        try {
            String sql = "DELETE FROM " + GlobalConfigUtils.getGlobalConfig().getTableName() + " WHERE login_id = ?";
            int num = jdbcTemplate.update(sql, loginId);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider deleteByLoginId failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 用于定时执行数据清理的线程池
     */
    private volatile ScheduledExecutorService executorService;

    /**
     * 初始化清理任务，每天凌晨第一秒执行一次
     */
    private void initCleanThread() {
        // 双重校验构造一个单例的ScheduledThreadPool
        if (this.executorService == null) {
            synchronized (JdbcAuthProvider.class) {
                if (this.executorService == null) {
                    this.executorService = Executors.newScheduledThreadPool(1);
                    // 获取当前时间
                    LocalDateTime now = LocalDateTime.now();
                    // 获取明天凌晨第一秒的时间，如2023-08-25 00:00:01:000
                    LocalDateTime tomorrow = now.plusDays(1).withHour(0).withMinute(0).withSecond(1).withNano(0);
                    // 计算初始延迟时间（单位-毫秒）
                    long initialDelay = ChronoUnit.MILLIS.between(now, tomorrow);
                    this.executorService.scheduleAtFixedRate(() -> {
                        log.info("JdbcAuthProvider clean execute at: {}", LocalDateTime.now());
                        try {
                            // 执行清理方法
                            this.clean();
                        } catch (Exception e2) {
                            log.error("JdbcAuthProvider cleanThread Exception: {e2}", e2);
                        }
                    }, initialDelay/*首次延迟多长时间后执行*/, 24 * 60 * 60 * 1000/*定时任务间隔时间，这里设置的是24小时*/, TimeUnit.MILLISECONDS);
                }
            }
        }
        log.info("JdbcAuthProvider cleanThread init successful!");
    }


    private void clean() {
        try {
            String sql = "DELETE FROM " + GlobalConfigUtils.getGlobalConfig().getTableName() + " WHERE credentials_expire_time < ?";
            int num = jdbcTemplate.update(sql, System.currentTimeMillis());
            log.info("JdbcAuthProvider clean num: {}", num);
        } catch (Exception e) {
            log.error("JdbcAuthProvider clean failed, Exception: {e}", e);
        }
    }
}