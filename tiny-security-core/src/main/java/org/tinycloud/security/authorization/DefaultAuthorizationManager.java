package org.tinycloud.security.authorization;

import jakarta.servlet.http.HttpServletRequest;
import org.tinycloud.security.annotation.AnnotationUtils;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;

/**
 * 默认授权管理器
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public class DefaultAuthorizationManager implements AuthorizationManager {
    private final PermissionMode permissionMode;
    private final AuthorizationInfoGet authorizationInfoGet;

    /**
     * 构造默认授权管理器。
     *
     * @param permissionMode       权限校验模式
     * @param authorizationInfoGet 角色权限数据提供器
     */
    public DefaultAuthorizationManager(PermissionMode permissionMode, AuthorizationInfoGet authorizationInfoGet) {
        this.permissionMode = permissionMode == null ? PermissionMode.ANNOTATION : permissionMode;
        this.authorizationInfoGet = authorizationInfoGet;
    }

    /**
     * 执行授权并返回授权结果。
     *
     * @param request 当前请求
     * @param method  目标方法
     * @param context 安全上下文
     * @return 授权决策
     */
    @Override
    public AuthorizationDecision authorize(HttpServletRequest request, Method method, SecurityContext context) {
        if (context == null) {
            context = new SecurityContext();
        }
        LoginSubject subject = context.getLoginSubject();
        if (this.permissionMode == PermissionMode.ANNOTATION && !AnnotationUtils.hasAuthorizationAnnotation(method)) {
            return AuthorizationDecision.grant();
        }

        Set<String> roleSet = this.authorizationInfoGet != null ? this.authorizationInfoGet.getRoleSet(subject) : Collections.emptySet();
        Set<String> permissionSet = this.authorizationInfoGet != null ? this.authorizationInfoGet.getPermissionSet(subject) : Collections.emptySet();
        // 保存角色权限数据，引用传递，所以修改后会被保存到安全上下文中
        context.setRoleSet(roleSet);
        context.setPermissionSet(permissionSet);

        boolean hasPermission = this.permissionMode == PermissionMode.URL
                ? AuthorizationEvaluator.checkUrlPermission(request, permissionSet)
                : AuthorizationEvaluator.checkPermission(method, permissionSet);
        boolean hasRole = AuthorizationEvaluator.checkRole(method, roleSet);
        return hasPermission && hasRole ? AuthorizationDecision.grant() : AuthorizationDecision.deny();
    }
}
