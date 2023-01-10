package org.bluewind.authclient.provider;


/**
 * 操作token的接口
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public interface AuthStore {

    String TOKENSTYLE_UUID = "uuid";

    String TOKENSTYLE_SNOWFLAKE = "snowflake";

    /**
     * 刷新token
     * @param token
     * @return
     */
    boolean refreshToken(String token);

    /**
     * 检查token是否失效
     * @param token
     * @return
     */
    boolean checkToken(String token);

    /**
     * 创建一个新的token
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    String createToken(Object loginId);

    /**
     * 根据token，获取当前登录用户的loginId
     * @param token
     * @return
     */
    Object getLoginId(String token);

    /**
     * 删除token
     * @param token
     * @return
     */
    boolean deleteToken(String token);

    /**
     * 通过loginId删除token---------暂未实现，还没想好思路
     * @param loginId
     * @return
     */
    boolean deleteTokenByLoginId(Object loginId);
}
