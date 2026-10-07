package org.tinycloud.security.context;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

/**
 * <p>
 *     登录主体，包含登录账号id、登录凭证等信息
 * </p>
 *
 * <p><b>1.5.0 · 滚动发布安全</b>：会话是以 JSON 存在 Redis / JDBC 里的，而滚动发布期间新旧实例会并存，
 * 新实例写下的会话里可能带着旧实例不认识的字段。这里显式忽略未知字段——否则 Jackson 默认的
 * {@code FAIL_ON_UNKNOWN_PROPERTIES} 会让旧实例反序列化失败，{@code readValue} 返回 null，
 * 被上层当成"会话不存在"而把所有在线用户打成 401。
 *
 * <p>因此本类<b>只应增字段，不应改名或删除字段</b>；改字段语义时请按"新增字段 + 兼容旧字段"的方式演进。
 *
 * @author liuxingyu01
 * @since 2024-09-04 16:50
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginSubject implements Serializable {
    @Serial
    private static final long serialVersionUID = -1L;

    /**
     * 登录账号ID
     */
    private Object loginId;

    /**
     * 扩展信息
     */
    private Map<String, Object> extraInfo;

    /**
     * 登录时间
     */
    private Long loginTime;

    /**
     * 登录过期时间
     */
    private Long loginExpireTime;

     /**
      * 登录凭证
      */
     private String credentials;

    public Object getLoginId() {
        return loginId;
    }

    public void setLoginId(Object loginId) {
        this.loginId = loginId;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
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

     public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    @Override
    public String toString() {
        // credentials 为会话凭证，输出到日志会造成泄露，这里固定脱敏
        return "LoginSubject{" +
                "loginId=" + loginId +
                ", extraInfo=" + extraInfo +
                ", loginTime=" + loginTime +
                ", loginExpireTime=" + loginExpireTime +
                ", credentials=" + "****" +
                '}';
    }
}
