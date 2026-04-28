package org.tinycloud.security.event;

import java.util.Map;

/**
 * 登录成功事件
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class LoginSuccessEvent {
    private final Object loginId;
    private final String token;
    private final Map<String, Object> extraInfo;
    private final long timestamp;

    /**
     * 构造登录成功事件。
     *
     * @param loginId   登录账号ID
     * @param token     登录令牌
     * @param extraInfo 扩展信息
     * @param timestamp 事件时间戳
     */
    public LoginSuccessEvent(Object loginId, String token, Map<String, Object> extraInfo, long timestamp) {
        this.loginId = loginId;
        this.token = token;
        this.extraInfo = extraInfo;
        this.timestamp = timestamp;
    }

    /**
     * 获取登录账号ID。
     *
     * @return 登录账号ID
     */
    public Object getLoginId() {
        return loginId;
    }

    /**
     * 获取登录令牌。
     *
     * @return 登录令牌
     */
    public String getToken() {
        return token;
    }

    /**
     * 获取扩展信息。
     *
     * @return 扩展信息
     */
    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    /**
     * 获取事件时间戳。
     *
     * @return 时间戳
     */
    public long getTimestamp() {
        return timestamp;
    }
}
