package org.tinycloud.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
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

    private Integer maxConcurrentLogins = 0;

    private Boolean exceptionTranslationEnabled = true;

    private Boolean forceHttpStatus200 = false;

    @Deprecated
    private String[] addPath;

    private String[] includePath;

    private String[] excludePath = new String[]{};

    public Boolean getBanner() { return banner; }
    public void setBanner(Boolean banner) { this.banner = banner; }
    public String getStoreType() { return storeType; }
    public void setStoreType(String storeType) { this.storeType = storeType; }
    public String getTokenName() { return tokenName; }
    public void setTokenName(String tokenName) { this.tokenName = tokenName; }
    public Integer getTimeout() { return timeout; }
    public void setTimeout(Integer timeout) { this.timeout = timeout; }
    public String getCredentialsStyle() { return credentialsStyle; }
    public void setCredentialsStyle(String credentialsStyle) { this.credentialsStyle = credentialsStyle; }
    public String getTableName() { return tableName; }
    public void setTableName(String tableName) { this.tableName = tableName; }
    public Boolean getAuthorizationEnabled() { return authorizationEnabled; }
    public void setAuthorizationEnabled(Boolean authorizationEnabled) { this.authorizationEnabled = authorizationEnabled; }
    public PermissionMode getPermCheckMode() { return permCheckMode; }
    public void setPermCheckMode(PermissionMode permCheckMode) { this.permCheckMode = permCheckMode; }
    public String getJwtSecret() { return jwtSecret; }
    public void setJwtSecret(String jwtSecret) { this.jwtSecret = jwtSecret; }
    public String getJwtSubject() { return jwtSubject; }
    public void setJwtSubject(String jwtSubject) { this.jwtSubject = jwtSubject; }
    public Integer getMaxConcurrentLogins() { return maxConcurrentLogins; }
    public void setMaxConcurrentLogins(Integer maxConcurrentLogins) { this.maxConcurrentLogins = maxConcurrentLogins; }
    public Boolean getExceptionTranslationEnabled() { return exceptionTranslationEnabled; }
    public void setExceptionTranslationEnabled(Boolean exceptionTranslationEnabled) { this.exceptionTranslationEnabled = exceptionTranslationEnabled; }
    public Boolean getForceHttpStatus200() { return forceHttpStatus200; }
    public void setForceHttpStatus200(Boolean forceHttpStatus200) { this.forceHttpStatus200 = forceHttpStatus200; }
    @Deprecated
    public String[] getAddPath() { return addPath; }
    @Deprecated
    public void setAddPath(String[] addPath) { this.addPath = addPath; }
    public String[] getIncludePath() {
        String[] mergedPaths = CommonUtil.mergeAndDeduplicate(this.includePath, this.addPath);
        if (mergedPaths == null || mergedPaths.length == 0) {
            return new String[]{"/**"};
        }
        return mergedPaths;
    }
    public void setIncludePath(String[] includePath) { this.includePath = includePath; }
    public String[] getExcludePath() { return excludePath; }
    public void setExcludePath(String[] excludePath) { this.excludePath = excludePath; }
}
