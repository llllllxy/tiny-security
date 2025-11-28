package org.tinycloud.security.provider;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

/**
 * <p>
 *     登录主体，包含登录账号id、登录凭证等信息
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-09-04 16:50
 */
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
        return "LoginSubject{" +
                "loginId=" + loginId +
                "extraInfo=" + extraInfo +
                ", loginTime=" + loginTime +
                ", loginExpireTime=" + loginExpireTime +
                ", credentials=" + credentials +
                '}';
    }
}
