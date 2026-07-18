package org.tinycloud.security.session;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Assert;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.exception.ConcurrentLoginOverLimitException;
import org.tinycloud.security.util.JsonUtil;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * JDBC 会话仓储实现
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class JdbcSessionRepository implements SessionRepository, DisposableBean {
    private static final Logger log = LoggerFactory.getLogger(JdbcSessionRepository.class);

    private final JdbcTemplate jdbcTemplate;
    private final String tableName;

    /**
     * 用于定时执行数据清理的线程池
     */
    private volatile ScheduledExecutorService executorService;
    /**
     * 基础初始延迟：10分钟
     */
    private static final long INITIAL_DELAY_BASE = 10 * 60 * 1000;
    /**
     * 最大随机延迟：6000秒
     */
    private static final int RANDOM_DELAY_MAX_SECONDS = 6000;
    /**
     * 定时任务执行周期：24小时（毫秒）
     */
    private static final long PERIOD = 24 * 60 * 60 * 1000;

    /**
     * 构造 JDBC 会话仓储并启动清理线程。
     *
     * @param jdbcTemplate JDBC 模板
     * @param tableName    会话表名
     */
    public JdbcSessionRepository(JdbcTemplate jdbcTemplate, String tableName) {
        this.jdbcTemplate = jdbcTemplate;
        this.tableName = tableName;
        this.initCleanThread();
    }

    /**
     * 保存会话记录。
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
            String sql = "INSERT INTO " + tableName + " (credentials,login_id,login_subject,credentials_expire_time) VALUES (?,?,?,?)";
            int num = jdbcTemplate.update(
                    sql,
                    subject.getCredentials(),
                    String.valueOf(subject.getLoginId()),
                    JsonUtil.writeValueAsString(subject),
                    subject.getLoginExpireTime()
            );
            return num > 0;
        } catch (ConcurrentLoginOverLimitException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("JdbcSessionRepository save failed, Exception：", e);
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
            String sql = "SELECT credentials_expire_time FROM " + tableName + " WHERE credentials = ? AND credentials_expire_time > ?";
            List<Map<String, Object>> resultList = this.jdbcTemplate.queryForList(sql, credentials, System.currentTimeMillis());
            return !resultList.isEmpty();
        } catch (Exception e) {
            log.error("JdbcSessionRepository checkByCredentials failed, Exception: ", e);
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
            String sql = "SELECT login_subject FROM " + tableName + " WHERE credentials = ? AND credentials_expire_time > ?";
            List<Map<String, Object>> resultList = this.jdbcTemplate.queryForList(sql, credentials, System.currentTimeMillis());
            if (!resultList.isEmpty()) {
                String content = resultList.get(0).get("login_subject").toString();
                return JsonUtil.readValue(content, LoginSubject.class);
            }
            return null;
        } catch (Exception e) {
            log.error("JdbcSessionRepository getSubject failed, Exception：", e);
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
            String sql = "UPDATE " + tableName + " SET credentials_expire_time = ?, login_subject = ? WHERE credentials = ?";
            int num = jdbcTemplate.update(sql, subject.getLoginExpireTime(), JsonUtil.writeValueAsString(subject), credentials);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcSessionRepository refreshByCredentials failed, Exception: ", e);
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
            String sql = "DELETE FROM " + tableName + " WHERE credentials = ?";
            int num = jdbcTemplate.update(sql, credentials);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcSessionRepository deleteByCredentials failed, Exception: ", e);
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
            String sql = "DELETE FROM " + tableName + " WHERE login_id = ?";
            int num = jdbcTemplate.update(sql, loginId);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcSessionRepository deleteByLoginId failed, Exception: ", e);
            return false;
        }
    }

    /**
     * 统计指定账号有效在线会话数。
     */
    @Override
    public int countValidOnlineSessions(Object loginId) {
        String sql = "SELECT COUNT(1) FROM " + tableName + " WHERE login_id = ? AND credentials_expire_time > ?";
        try {
            Long count = jdbcTemplate.queryForObject(sql, Long.class, loginId, System.currentTimeMillis());
            return count == null ? 0 : count.intValue();
        } catch (Exception e) {
            log.error("JdbcSessionRepository countValidOnlineSessions failed", e);
            return 0;
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
        log.info("账号{}当前有效在线人数：{}，最大限制：{}", loginId, currentOnlineCount, maxConcurrentLogins);
        return currentOnlineCount < maxConcurrentLogins;
    }

    /**
     * 初始化清理线程
     */
    private void initCleanThread() {
        if (this.executorService == null) {
            synchronized (JdbcSessionRepository.class) {
                if (this.executorService == null) {
                    this.executorService = Executors.newScheduledThreadPool(1);
                    long randomDelaySeconds = ThreadLocalRandom.current().nextInt(RANDOM_DELAY_MAX_SECONDS);
                    long initialDelay = INITIAL_DELAY_BASE + randomDelaySeconds * 1000L;
                    this.executorService.scheduleAtFixedRate(() -> {
                        log.info("JdbcSessionRepository clean execute at: {}", LocalDateTime.now());
                        this.clean();
                    }, initialDelay, PERIOD, TimeUnit.MILLISECONDS);
                }
            }
        }
    }

    /**
     * 执行过期会话清理。
     */
    private void clean() {
        try {
            String sql = "DELETE FROM " + tableName + " WHERE credentials_expire_time < ?";
            int num = jdbcTemplate.update(sql, System.currentTimeMillis());
            log.info("JdbcSessionRepository clean num: {}", num);
        } catch (Exception e) {
            log.error("JdbcSessionRepository clean failed, Exception: ", e);
        }
    }

    /**
     * 在 Spring 容器关闭时停止过期会话清理线程，防止线程泄露。
     */
    @Override
    public void destroy() {
        ScheduledExecutorService executor = this.executorService;
        if (executor != null) {
            executor.shutdownNow();
        }
    }
}
