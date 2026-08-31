package org.tinycloud.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.tinycloud.security.enums.CookieSameSite;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.util.CommonUtil;


/**
 * tiny-security映射配置类--映射yml里面的配置
 *
 * @author liuxingyu01
 * @since 2023-01-06-9:33
 **/
@ConfigurationProperties(prefix = "tiny-security")
public class AuthProperties {

    private Boolean banner = true;

    private String storeType = "single";

    private String tokenName = "token";

    private Integer timeout = 1800;

    private String credentialsStyle = "uuid";

    private String tableName = "t_auth_storage";

    private Boolean authorizationEnabled = false;

    private PermissionMode permCheckMode;

    private String jwtSecret;

    private String jwtSubject;

    /**
     * jwt自身有效期（秒），默认30天（2592000秒）
     */
    private Integer jwtTimeout = 30 * 24 * 60 * 60;

    private Integer maxConcurrentLogins = 0;

    private Boolean exceptionTranslationEnabled = true;

    private Boolean forceHttpStatus200 = false;

    /**
     * 是否启用 Cookie 模式（登录写 Cookie、登出清理 Cookie、从 Cookie 读取 token），
     * 默认 false（纯 token 模式，适配前后端分离项目；前后端不分离项目需开启）
     */
    private Boolean enableCookie = false;

    /**
     * 是否允许从 URL 参数中读取 token。
     * <p>默认 false：URL 参数传 token 会进入访问日志、Referer 等渠道造成凭证泄露，非必要不建议开启。
     * 开启后兼容历史行为（header 无 token 时回退到 {@code ?tokenName=xxx}）。
     */
    private Boolean enableUrlToken = false;

    /**
     * Cookie 是否仅通过 HTTPS 传输，默认 false（本地 http 调试友好，生产环境建议开启）
     */
    private Boolean cookieSecure = false;

    /**
     * Cookie SameSite 属性，默认 LAX
     */
    private CookieSameSite cookieSameSite = CookieSameSite.LAX;

    @Deprecated
    private String[] addPath;

    private String[] includePath;

    private String[] excludePath = new String[]{};

    public Boolean getBanner() {
        return banner;
    }

    public void setBanner(Boolean banner) {
        this.banner = banner;
    }

    public String getStoreType() {
        return storeType;
    }

    public void setStoreType(String storeType) {
        this.storeType = storeType;
    }

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public String getCredentialsStyle() {
        return credentialsStyle;
    }

    public void setCredentialsStyle(String credentialsStyle) {
        this.credentialsStyle = credentialsStyle;
    }

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    public Boolean getAuthorizationEnabled() {
        return authorizationEnabled;
    }

    public void setAuthorizationEnabled(Boolean authorizationEnabled) {
        this.authorizationEnabled = authorizationEnabled;
    }

    public PermissionMode getPermCheckMode() {
        return permCheckMode;
    }

    public void setPermCheckMode(PermissionMode permCheckMode) {
        this.permCheckMode = permCheckMode;
    }

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public String getJwtSubject() {
        return jwtSubject;
    }

    public void setJwtSubject(String jwtSubject) {
        this.jwtSubject = jwtSubject;
    }

    public Integer getJwtTimeout() {
        return jwtTimeout;
    }

    public void setJwtTimeout(Integer jwtTimeout) {
        this.jwtTimeout = jwtTimeout;
    }

    public Integer getMaxConcurrentLogins() {
        return maxConcurrentLogins;
    }

    public void setMaxConcurrentLogins(Integer maxConcurrentLogins) {
        this.maxConcurrentLogins = maxConcurrentLogins;
    }

    public Boolean getExceptionTranslationEnabled() {
        return exceptionTranslationEnabled;
    }

    public void setExceptionTranslationEnabled(Boolean exceptionTranslationEnabled) {
        this.exceptionTranslationEnabled = exceptionTranslationEnabled;
    }

    public Boolean getForceHttpStatus200() {
        return forceHttpStatus200;
    }

    public void setForceHttpStatus200(Boolean forceHttpStatus200) {
        this.forceHttpStatus200 = forceHttpStatus200;
    }

    public Boolean getCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(Boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }

    public Boolean getEnableCookie() {
        return enableCookie;
    }

    public void setEnableCookie(Boolean enableCookie) {
        this.enableCookie = enableCookie;
    }

    public Boolean getEnableUrlToken() {
        return enableUrlToken;
    }

    public void setEnableUrlToken(Boolean enableUrlToken) {
        this.enableUrlToken = enableUrlToken;
    }

    public CookieSameSite getCookieSameSite() {
        return cookieSameSite;
    }

    public void setCookieSameSite(CookieSameSite cookieSameSite) {
        this.cookieSameSite = cookieSameSite;
    }

    @Deprecated
    public String[] getAddPath() {
        return addPath;
    }

    @Deprecated
    public void setAddPath(String[] addPath) {
        this.addPath = addPath;
    }

    public String[] getIncludePath() {
        String[] mergedPaths = CommonUtil.mergeAndDeduplicate(this.includePath, this.addPath);
        if (mergedPaths == null || mergedPaths.length == 0) {
            return new String[]{"/**"};
        }
        return mergedPaths;
    }

    public void setIncludePath(String[] includePath) {
        this.includePath = includePath;
    }

    public String[] getExcludePath() {
        return excludePath;
    }

    public void setExcludePath(String[] excludePath) {
        this.excludePath = excludePath;
    }
}
