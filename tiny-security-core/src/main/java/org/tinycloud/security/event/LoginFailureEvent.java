package org.tinycloud.security.event;

import java.util.Map;

/**
 * 登录失败事件
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class LoginFailureEvent {
    private final Object loginId;
    private final Map<String, Object> extraInfo;
    private final String errorMessage;
    private final long timestamp;

    /**
     * 构造登录失败事件。
     *
     * @param loginId      登录账号ID
     * @param extraInfo    扩展信息
     * @param errorMessage 失败原因
     * @param timestamp    事件时间戳
     */
    public LoginFailureEvent(Object loginId, Map<String, Object> extraInfo, String errorMessage, long timestamp) {
        this.loginId = loginId;
        this.extraInfo = extraInfo;
        this.errorMessage = errorMessage;
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
     * 获取扩展信息。
     *
     * @return 扩展信息
     */
    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    /**
     * 获取失败原因。
     *
     * @return 失败原因
     */
    public String getErrorMessage() {
        return errorMessage;
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
