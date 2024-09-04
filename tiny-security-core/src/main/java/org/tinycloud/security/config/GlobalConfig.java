package org.tinycloud.security.config;


import java.io.Serializable;

/**
 * <p>
 * </p>
 *
 * @author liuxingyu01
 * @since 2024-04-2024/4/15 23:33
 */
public class GlobalConfig implements Serializable {
    /**
     * 是否开启 LOGO 打印
     */
    private boolean banner = true;

    private String version;

    private String storeType = "redis";

    private String tokenName = "token";

    private Integer timeout = 3600;

    private String tokenStyle = "uuid";

    private String tokenPrefix;

    private String tableName = "s_auth_token";

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

    public String getTokenStyle() {
        return tokenStyle;
    }

    public void setTokenStyle(String tokenStyle) {
        this.tokenStyle = tokenStyle;
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
}
