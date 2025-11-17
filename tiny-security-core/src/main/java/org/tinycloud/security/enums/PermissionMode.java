package org.tinycloud.security.enums;

/**
 * 权限校验模式
 * 1. annotation：基于注解的权限校验模式
 * 2. url：基于URL的权限校验模式
 *
 * @author liuxingyu01
 * @since 2025-09-16
 */
public enum PermissionMode {
    /**
     * 权限校验模式
     */
    ANNOTATION,
    /**
     * 角色校验模式
     */
    URL;

    private PermissionMode() {
    }
}
