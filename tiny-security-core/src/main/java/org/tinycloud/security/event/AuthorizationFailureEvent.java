package org.tinycloud.security.event;

/**
 * 鉴权失败事件
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class AuthorizationFailureEvent {
    private final Object loginId;
    private final String requestPath;
    private final String methodName;
    private final String reason;
    private final long timestamp;

    /**
     * 构造鉴权失败事件。
     *
     * @param loginId     登录账号ID
     * @param requestPath 请求路径
     * @param methodName  方法名
     * @param reason      失败原因
     * @param timestamp   事件时间戳
     */
    public AuthorizationFailureEvent(Object loginId, String requestPath, String methodName, String reason, long timestamp) {
        this.loginId = loginId;
        this.requestPath = requestPath;
        this.methodName = methodName;
        this.reason = reason;
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
     * 获取请求路径。
     *
     * @return 请求路径
     */
    public String getRequestPath() {
        return requestPath;
    }

    /**
     * 获取鉴权方法名。
     *
     * @return 方法名
     */
    public String getMethodName() {
        return methodName;
    }

    /**
     * 获取失败原因。
     *
     * @return 失败原因
     */
    public String getReason() {
        return reason;
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
