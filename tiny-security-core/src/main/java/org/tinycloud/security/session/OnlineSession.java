package org.tinycloud.security.session;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

/**
 * 在线会话视图（查询结果，只读）。
 *
 * <p>用于「在线用户列表」这类运维查询。它<b>刻意不含 {@code credentials}</b> ——
 * 会话凭证就是 bearer token 的签名原文，等同于用户身份凭据，一旦出现在列表接口的响应体里，
 * 拿到响应的人就能直接接管会话。给前端一个可用于定位会话、但无法反推凭证的标识就够了，
 * 这就是 {@link #sessionId} 的用途。
 *
 * <p><b>{@link #sessionId} 不是加密，是摘要</b>：它是凭证的 SHA-256 值。凭证本身是
 * 122 bit 随机 UUID，无法通过摘要反推或暴力枚举；但它<b>不做身份验证</b>——
 * 能拿到 {@code sessionId} 的人仍然可以调用踢人接口。它的价值只在于"响应体里不再出现真凭证"，
 * 因此踢人接口本身<b>仍必须做权限校验</b>（与列表接口同等保护）。
 *
 * @author liuxingyu01
 * @since 1.5.0
 */
public class OnlineSession implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 登录账号ID
     */
    private Object loginId;

    /**
     * 登录时间（毫秒时间戳）
     */
    private Long loginTime;

    /**
     * 登录过期时间（毫秒时间戳）
     */
    private Long loginExpireTime;

    /**
     * 登录时存入的扩展信息。
     *
     * <p>这是<b>业务自己写进去的</b>（{@code login(loginId, extraInfo)}），框架原样返回。
     * 常见用法是存 IP、浏览器、操作系统、userId 等。
     * 注意全量列表会把每个会话的 extraInfo 一起带出去，<b>请勿在其中存放敏感信息</b>。
     */
    private Map<String, Object> extraInfo;

    /**
     * 会话标识：凭证的 SHA-256 摘要。
     *
     * <p>用于在列表 → 踢人的链路里定位会话，同时保证原始凭证不出后端。
     * 配合 {@code AuthProvider.deleteBySessionId(loginId, sessionId)} 使用。
     */
    private String sessionId;

    public Object getLoginId() {
        return loginId;
    }

    public void setLoginId(Object loginId) {
        this.loginId = loginId;
    }

    public Long getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(Long loginTime) {
        this.loginTime = loginTime;
    }

    public Long getLoginExpireTime() {
        return loginExpireTime;
    }

    public void setLoginExpireTime(Long loginExpireTime) {
        this.loginExpireTime = loginExpireTime;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    @Override
    public String toString() {
        return "OnlineSession{" +
                "loginId=" + loginId +
                ", loginTime=" + loginTime +
                ", loginExpireTime=" + loginExpireTime +
                ", extraInfo=" + extraInfo +
                ", sessionId='" + sessionId + '\'' +
                '}';
    }
}
