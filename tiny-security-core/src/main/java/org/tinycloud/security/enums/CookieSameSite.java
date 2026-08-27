package org.tinycloud.security.enums;

/**
 * Cookie SameSite 属性
 * 1. STRICT：同站请求才携带 Cookie，最严格
 * 2. LAX：同站请求携带，跨站顶级导航（GET）携带，默认推荐值
 * 3. NONE：跨站也携带，但必须同时启用 Secure（HTTPS）
 *
 * @author liuxingyu01
 * @since 2026-08-27
 */
public enum CookieSameSite {
    /**
     * 同站请求才携带
     */
    STRICT("Strict"),
    /**
     * 同站请求携带，跨站顶级导航（GET）携带
     */
    LAX("Lax"),
    /**
     * 跨站也携带，必须同时启用 Secure
     */
    NONE("None");

    private final String value;

    CookieSameSite(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
