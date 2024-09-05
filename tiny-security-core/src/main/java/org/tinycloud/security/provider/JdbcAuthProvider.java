package org.tinycloud.security.provider;

import org.springframework.util.Assert;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.util.JsonUtil;
import org.tinycloud.security.util.TokenGenUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
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
    final static Logger log = LoggerFactory.getLogger(JdbcAuthProvider.class);

    private final JdbcTemplate jdbcTemplate;

    public JdbcAuthProvider(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        // 同时初始化定时任务
        this.initCleanThread();
    }

    /**
     * 刷新token有效时间
     *
     * @param token 令牌
     * @return true成功，false失败
     */
    @Override
    public boolean refreshToken(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String sql = "update " + GlobalConfigUtils.getGlobalConfig().getTableName() + " set token_expire_time = ? where token_str = ?";
            int num = jdbcTemplate.update(sql, System.currentTimeMillis() + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000, token);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider refreshToken failed, Exception: {e}", e);
            return false;
        }
    }

    @Override
    public boolean refreshToken(String token, LoginSubject subject) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String sql = "update " + GlobalConfigUtils.getGlobalConfig().getTableName() + " set token_expire_time = ?, login_subject = ? where token_str = ?";
            int num = jdbcTemplate.update(sql, System.currentTimeMillis() + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000, JsonUtil.writeValueAsString(subject), token);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider refreshToken failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 检查token是否失效
     *
     * @param token 令牌
     * @return true未失效，false已失效
     */
    @Override
    public boolean checkToken(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String sql = "select token_expire_time from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where token_str = ?";
            List<Map<String, Object>> resultList = jdbcTemplate.queryForList(sql, token);
            if (!resultList.isEmpty()) {
                long tokenExpireTime = Long.parseLong(resultList.get(0).get("token_expire_time").toString());
                return tokenExpireTime > System.currentTimeMillis();
            } else {
                return false;
            }
        } catch (Exception e) {
            log.error("JdbcAuthProvider checkToken failed, Exception: {e}", e);
            return false;
        }
    }

    @Override
    public LoginSubject getSubject(String token) {
        Assert.hasText(token, "The token cannot be empty!");
        try {
            String sql = "select login_subject from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where token_str = ?";
            List<Map<String, Object>> resultList = jdbcTemplate.queryForList(sql, token);
            if (!resultList.isEmpty()) {
                String content = resultList.get(0).get("login_subject").toString();
                return JsonUtil.readValue(content, LoginSubject.class);
            }
            return null;
        } catch (Exception e) {
            log.error("RedisAuthProvider getSubject failed, Exception：{e}", e);
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
    public String createToken(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null!");
        try {
            String token = TokenGenUtil.genTokenStr(GlobalConfigUtils.getGlobalConfig().getTokenStyle());
            LoginSubject subject = new LoginSubject();
            subject.setLoginId(loginId);
            long currentTime = System.currentTimeMillis();
            subject.setLoginTime(currentTime);
            subject.setLoginExpireTime(currentTime + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000L);
            String sql = "insert into " + GlobalConfigUtils.getGlobalConfig().getTableName() + " (token_str,login_id,login_subject,token_expire_time) values (?,?,?,?)";
            int num = jdbcTemplate.update(sql, token, String.valueOf(loginId), JsonUtil.writeValueAsString(subject), System.currentTimeMillis() + GlobalConfigUtils.getGlobalConfig().getTimeout() * 1000);
            return num > 0 ? token : null;
        } catch (Exception e) {
            log.error("JdbcAuthProvider createToken failed, Exception: {e}", e);
            return null;
        }
    }

    /**
     * 根据token，获取loginId
     *
     * @param token 令牌
     * @return loginId
     */
    @Override
    public Object getLoginId(String token) {
        Assert.hasText(token, "The token cannot be empty！");
        try {
            String sql = "select login_id from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where token_str = ?";
            List<Map<String, Object>> resultList = jdbcTemplate.queryForList(sql, token);
            if (!resultList.isEmpty()) {
                return resultList.get(0).get("login_id");
            }
            return null;
        } catch (Exception e) {
            log.error("JdbcAuthProvider getLoginId failed, Exception: {e}", e);
            return null;
        }
    }

    /**
     * 删除token
     *
     * @param token 令牌
     * @return true成功，false失败
     */
    @Override
    public boolean deleteToken(String token) {
        Assert.hasText(token, "The token cannot be empty！");
        try {
            String sql = "delete from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where token_str = ?";
            int num = jdbcTemplate.update(sql, token);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider deleteToken failed, Exception: {e}", e);
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
    public boolean deleteTokenByLoginId(Object loginId) {
        Assert.notNull(loginId, "The loginId cannot be null！");
        try {
            String sql = "delete from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where login_id = ?";
            int num = jdbcTemplate.update(sql, loginId);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider deleteTokenByLoginId failed, Exception: {e}", e);
            return false;
        }
    }

    /**
     * 用于定时执行数据清理的线程池
     */
    private volatile ScheduledExecutorService executorService;

    /**
     * 初始化清理任务，每天执行一次
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
            String sql = "delete from " + GlobalConfigUtils.getGlobalConfig().getTableName() + " where token_expire_time < ?";
            int num = jdbcTemplate.update(sql, System.currentTimeMillis());
            log.info("JdbcAuthProvider clean num: {}", num);
        } catch (Exception e) {
            log.error("JdbcAuthProvider clean failed, Exception: {e}", e);
        }
    }
}
