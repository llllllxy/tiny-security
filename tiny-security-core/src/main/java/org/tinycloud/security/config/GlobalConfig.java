package org.tinycloud.security.config;


import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.interfaces.PermissionInfoInterface;
import org.tinycloud.security.provider.AuthProvider;

import java.io.Serializable;

/**
 * <p>
 *     全局配置类
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-04-2024/4/15 23:33
 */
public class GlobalConfig implements Serializable {

    private AuthProvider authProvider;

    private PermissionInfoInterface permissionInfoInterface;

    /**
     * 是否开启 LOGO 打印
     */
    private boolean banner = true;

    private String version;

    private String storeType;

    private String tokenName;

    private Integer timeout;

    private String credentialsStyle;

    private String tokenPrefix;

    private String tableName;

    private PermissionMode permCheckMode;

    private String jwtSecret;

    private String jwtSubject;

    public AuthProvider getAuthProvider() {
        return authProvider;
    }

    public void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    public PermissionInfoInterface getPermissionInfoInterface() {
        return permissionInfoInterface;
    }

    public void setPermissionInfoInterface(PermissionInfoInterface permissionInfoInterface) {
        this.permissionInfoInterface = permissionInfoInterface;
    }

    public boolean isBanner() {
        return banner;
    }

    public void setBanner(boolean banner) {
        this.banner = banner;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
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

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
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