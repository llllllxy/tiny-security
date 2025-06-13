package org.tinycloud.security.provider;

import java.io.Serializable;
import java.util.Map;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-09-04 16:50
 */
public class LoginSubject implements Serializable {
    private static final long serialVersionUID = -1L;

    /**
     * 租户ID
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

    @Override
    public String toString() {
        return "LoginSubject{" +
                "loginId=" + loginId +
                "extraInfo=" + extraInfo +
                ", loginTime=" + loginTime +
                ", loginExpireTime=" + loginExpireTime +
                '}';
    }
}
