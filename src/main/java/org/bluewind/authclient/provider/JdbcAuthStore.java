package org.bluewind.authclient.provider;

import org.bluewind.authclient.AuthProperties;
import org.bluewind.authclient.consts.AuthConsts;
import org.bluewind.authclient.util.Snowflake;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;


/**
 * 操作token的接口（通过jdbc实现）
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class JdbcAuthStore implements AuthStore {
    final static Logger log = LoggerFactory.getLogger(JdbcAuthStore.class);

    private final JdbcTemplate jdbcTemplate;

    private final AuthProperties authProperties;

    public JdbcAuthStore(JdbcTemplate jdbcTemplate, AuthProperties authProperties) {
        this.jdbcTemplate = jdbcTemplate;
        this.authProperties = authProperties;
    }


    /**
     * 刷新token
     * @param token
     * @return
     */
    public boolean refreshToken(String token) {
        return true;
    }

    /**
     * 检查token是否失效
     * @param token
     * @return
     */
    public boolean checkToken(String token) {
        return true;
    }

    /**
     * 创建一个新的token
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    public String createToken(Object loginId) {
        return null;
    }

    /**
     * 根据token，获取当前登录用户的loginId
     * @param token
     * @return
     */
    public Object getLoginId(String token) {
        return null;
    }

    /**
     * 删除token
     * @param token
     * @return
     */
    public boolean deleteToken(String token) {
        return true;
    }

    /**
     * 通过loginId删除token---------暂未实现，还没想好思路
     * @param loginId
     * @return
     */
    public boolean deleteTokenByLoginId(Object loginId) {
        return true;
    }

}
