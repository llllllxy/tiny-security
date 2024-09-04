package org.tinycloud.security.provider;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-09-04 16:50
 */
public class LoginSubject {

    /**
     * 租户ID
     */
    private Object loginId;

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
}
