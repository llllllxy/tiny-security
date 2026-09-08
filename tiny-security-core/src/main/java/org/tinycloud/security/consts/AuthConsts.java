package org.tinycloud.security.consts;


/**
 * 系统常量类
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public class AuthConsts {

    /**
     * 登录用户 令牌 Redis Key 前缀
     */
    public static final String AUTH_CREDENTIALS_KEY = "tiny:security:credentials:";

    /**
     * Redis 列表 Key 前缀：存储账号对应的所有在线凭证（credentials）
     */
    public static final String ONLINE_CREDENTIALS_KEY_PREFIX = "tiny:security:online:";

    /**
     * 无权限访问
     */
    public static final int CODE_NO_PERMISSION = 403;

    /**
     * 未登录或会话已失效
     */
    public static final int CODE_UNAUTHORIZED = 401;

    /**
     * 并发登录超量
     */
    public static final int CODE_CONCURRENT_LOGIN_OVER_LIMIT = 409;

    /**
     * 其他异常
     */
    public static final int CODE_OTHER_ERROR = 500;

    /**
     * JWT 令牌前缀
     */
    public static final String JWT_TOKEN_PREFIX = "Bearer ";
}
