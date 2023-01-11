package org.bluewind.authclient.provider;

import org.bluewind.authclient.AuthProperties;
import org.bluewind.authclient.util.AuthUtil;
import org.bluewind.authclient.util.CommonUtil;
import org.bluewind.authclient.util.Snowflake;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.UUID;


/**
 * 操作token和会话的接口（通过jdbc实现）
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class JdbcAuthProvider implements AuthProvider {
    final static Logger log = LoggerFactory.getLogger(JdbcAuthProvider.class);

    private final JdbcTemplate jdbcTemplate;

    private final AuthProperties authProperties;

    public JdbcAuthProvider(JdbcTemplate jdbcTemplate, AuthProperties authProperties) {
        this.jdbcTemplate = jdbcTemplate;
        this.authProperties = authProperties;
    }


    /**
     * 刷新token
     *
     * @param token
     * @return
     */
    @Override
    public boolean refreshToken(String token) {
        try {
            String sql = "update " + authProperties.getTableName() + " set token_expire_time = ? where token_str = ?";
            int num = jdbcTemplate.update(sql, CommonUtil.currentTimePlusSeconds(authProperties.getTimeout()), token);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider - refreshToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 检查token是否失效
     *
     * @param token
     * @return
     */
    @Override
    public boolean checkToken(String token) {
        try {
            String sql = "select token_str,login_id,token_expire_time from " + authProperties.getTableName() + " where token_str=?";
            Map<String, Object> resultMap = jdbcTemplate.queryForMap(sql, token);
            String tokenExpireTime = resultMap.get("token_expire_time").toString();
            return CommonUtil.timeCompare(tokenExpireTime);
        } catch (Exception e) {
            log.error("JdbcAuthProvider - checkToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 创建一个新的token
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    @Override
    public String createToken(Object loginId) {
        try {
            String token;
            if (authProperties.getTokenStyle().equals(TOKENSTYLE_SNOWFLAKE)) {
                token = Snowflake.nextId();
            } else {
                token = UUID.randomUUID().toString().replaceAll("-", "");
            }
            String sql = "insert into " + authProperties.getTableName() + " (token_str,login_id,token_expire_time) values (?,?,?)";
            int num = jdbcTemplate.update(sql, token, String.valueOf(loginId), CommonUtil.currentTimePlusSeconds(authProperties.getTimeout()));
            return num > 0 ? token : null;
        } catch (Exception e) {
            log.error("JdbcAuthProvider - createToken - 失败，Exception：{e}", e);
            return null;
        }
    }

    /**
     * 根据token，获取loginId
     *
     * @param token
     * @return
     */
    @Override
    public Object getLoginId(String token) {
        try {
            String sql = "select token_str,login_id,token_expire_time from " + authProperties.getTableName() + " where token_str=?";
            Map<String, Object> resulMap = jdbcTemplate.queryForMap(sql, token);
            return resulMap.get("login_id");
        } catch (Exception e) {
            log.error("JdbcAuthProvider - getLoginId - 失败，Exception：{e}", e);
            return null;
        }
    }

    /**
     * 获取当前登录用户的loginId
     *
     * @return
     */
    @Override
    public Object getLoginId() {
        try {
            String token = AuthUtil.getToken(this.authProperties.getTokenName());
            String sql = "select token_str,login_id,token_expire_time from " + authProperties.getTableName() + " where token_str=?";
            Map<String, Object> resulMap = jdbcTemplate.queryForMap(sql, token);
            return resulMap.get("login_id");
        } catch (Exception e) {
            log.error("JdbcAuthProvider - getLoginId - 失败，Exception：{e}", e);
            return null;
        }
    }

    /**
     * 删除token
     *
     * @param token
     * @return
     */
    @Override
    public boolean deleteToken(String token) {
        try {
            String sql = "delete from " + authProperties.getTableName() + " where token_str = ?";
            int num = jdbcTemplate.update(sql, token);
            return num > 0;
        } catch (Exception e) {
            log.error("JdbcAuthProvider - deleteToken - 失败，Exception：{e}", e);
            return false;
        }
    }

    /**
     * 通过loginId删除token---------暂未实现，还没想好思路
     *
     * @param loginId
     * @return
     */
    @Override
    public boolean deleteTokenByLoginId(Object loginId) {
        return true;
    }

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     */
    @Override
    public String login(Object loginId) {
        return this.createToken(loginId);
    }

    /**
     * 退出登录
     */
    @Override
    public void logout(HttpServletRequest request) {
        String token = AuthUtil.getToken(request, this.authProperties.getTokenName());
        this.deleteToken(token);
    }

    /**
     * 退出登录
     */
    @Override
    public void logout() {
        String token = AuthUtil.getToken(this.authProperties.getTokenName());
        this.deleteToken(token);
    }
}
