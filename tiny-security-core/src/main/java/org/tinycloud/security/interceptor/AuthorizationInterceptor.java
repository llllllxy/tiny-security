package org.tinycloud.security.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.interceptor.holder.AuthenticationHolder;
import org.tinycloud.security.interceptor.holder.AuthorizationHolder;
import org.tinycloud.security.interfaces.AuthorizationInfoGet;
import org.tinycloud.security.provider.LoginSubject;
import org.tinycloud.security.util.AuthUtil;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * 用户权限验证拦截器
 *
 * @author liuxingyu01
 * @version 2024-03-22-11:23
 **/
public class AuthorizationInterceptor implements HandlerInterceptor {

    /*
     * 进入controller层之前拦截请求
     * 返回值：表示是否将当前的请求拦截下来  false：拦截请求，请求别终止。true：请求不被拦截，继续执行
     * Object obj:表示被拦的请求的目标对象（controller中方法）
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        // 判断请求类型，如果是OPTIONS，直接返回
        String options = HttpMethod.OPTIONS.toString();
        if (options.equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return true;
        }
        LoginSubject subject = AuthenticationHolder.getLoginSubject();
        if (Objects.isNull(subject)) {
            throw new NoPermissionException();
        }
        Method method = ((HandlerMethod) handler).getMethod();
        // 如果权限模式为注解并且类上或方法上没有注解，则直接返回（提升性能，省的每次都调用获取权限角色列表）
        if (GlobalConfigUtils.getGlobalConfig().getPermCheckMode() == PermissionMode.ANNOTATION && !AuthUtil.hasPermissionAnnotation(method)) {
            return true;
        }
        AuthorizationInfoGet AuthorizationInfoGet = GlobalConfigUtils.getGlobalConfig().getAuthorizationInfoGet();
        Set<String> roleSet = AuthorizationInfoGet != null ? AuthorizationInfoGet.getRoleSet(subject) : Collections.emptySet();
        Set<String> permissionSet = AuthorizationInfoGet != null ? AuthorizationInfoGet.getPermissionSet(subject) : Collections.emptySet();
        AuthorizationHolder.setRoleSet(roleSet);
        AuthorizationHolder.setPermissionSet(permissionSet);

        boolean hasPermission = GlobalConfigUtils.getGlobalConfig().getPermCheckMode() == PermissionMode.URL
                ? AuthUtil.checkUrlPermission(request)
                : AuthUtil.checkPermission(method);
        boolean hasRole = AuthUtil.checkRole(method);
        if (hasPermission && hasRole) {
            return true;
        } else {
            // 权限和角色校验不通过
            // 直接抛出异常的话，就不需要return false了
            throw new NoPermissionException();
        }
    }


    /*
     * 处理请求完成后视图渲染之前的处理操作
     * 通过ModelAndView参数改变显示的视图，或发往视图的方法
     */
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
    }

    /*
     * 视图渲染之后的操作
     */
    @Override
    public void afterCompletion(HttpServletRequest arg0, HttpServletResponse arg1, Object arg2, Exception arg3) throws Exception {
        AuthorizationHolder.clearRoleSet();
        AuthorizationHolder.clearPermissionSet();
    }

}