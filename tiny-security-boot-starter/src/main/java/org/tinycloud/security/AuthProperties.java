package org.tinycloud.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.tinycloud.security.enums.PermissionMode;


/**
 * tiny-security映射配置类--映射yml里面的配置
 * @author liuxingyu01
 * @since 2023-01-06-9:33
 **/
@ConfigurationProperties(prefix = "tiny-security")
public class AuthProperties {

    private String storeType = "single";

    private String tokenName = "token";

    private Integer timeout = 1800;

    private String credentialsStyle = "uuid";

    private String tableName = "t_auth_storage";

    private PermissionMode permCheckMode;

    private String jwtSecret;

    private String jwtSubject;

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
}