package org.tinycloud.security.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.tinycloud.security.authorization.AuthorizationDecision;
import org.tinycloud.security.authorization.AuthorizationManager;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.context.SecurityContext;
import org.tinycloud.security.context.SecurityContextRepository;
import org.tinycloud.security.enums.PermissionMode;
import org.tinycloud.security.event.AuthorizationFailureEvent;
import org.tinycloud.security.event.NoopSecurityEventPublisher;
import org.tinycloud.security.event.SecurityEventPublisher;
import org.tinycloud.security.exception.NoPermissionException;
import org.tinycloud.security.exception.TinySecurityException;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.context.LoginSubject;
import org.tinycloud.security.util.AuthUtil;

import java.lang.reflect.Method;
import java.util.Objects;

/**
 * 用户权限角色验证拦截器
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
        Method method = ((HandlerMethod) handler).getMethod();
        // 与认证拦截器保持一致：被 @Ignore 标注的接口直接放行
        if (AuthUtil.checkIgnore(method)) {
            return true;
        }
        SecurityContext context = this.resolveSecurityContextRepository().loadContext(request);
        LoginSubject subject = (context == null ? null : context.getLoginSubject());
        if (Objects.isNull(subject)) {
            // 未登录属于认证失败，返回401语义更准确
            throw new UnAuthorizedException();
        }
        // 如果权限模式为注解并且类上或方法上没有注解，则直接返回（提升性能，省的每次都调用获取权限角色列表）
        if (GlobalConfigUtils.getGlobalConfig().getPermCheckMode() == PermissionMode.ANNOTATION && !AuthUtil.hasAuthorizationAnnotation(method)) {
            return true;
        }
        AuthorizationDecision decision = this.resolveAuthorizationManager().authorize(request, method, context);
        if (decision.isGranted()) {
            return true;
        } else {
            this.resolveSecurityEventPublisher().publishAuthorizationFailure(new AuthorizationFailureEvent(
                    subject.getLoginId(),
                    request.getRequestURI(),
                    method.getName(),
                    "permission_or_role_not_match",
                    System.currentTimeMillis()
            ));
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
        // 统一交由 AuthenticationInterceptor 在请求完成后清理安全上下文
    }

    private AuthorizationManager resolveAuthorizationManager() {
        AuthorizationManager authorizationManager = GlobalConfigUtils.getGlobalConfig().getAuthorizationManager();
        if (Objects.isNull(authorizationManager)) {
            throw new TinySecurityException("AuthorizationManager not initialized!");
        }
        return authorizationManager;
    }

    private SecurityContextRepository resolveSecurityContextRepository() {
        SecurityContextRepository repository = GlobalConfigUtils.getGlobalConfig().getSecurityContextRepository();
        if (Objects.isNull(repository)) {
            throw new TinySecurityException("SecurityContextRepository not initialized!");
        }
        return repository;
    }

    private SecurityEventPublisher resolveSecurityEventPublisher() {
        if (GlobalConfigUtils.getGlobalConfig() == null || GlobalConfigUtils.getGlobalConfig().getSecurityEventPublisher() == null) {
            return new NoopSecurityEventPublisher();
        }
        return GlobalConfigUtils.getGlobalConfig().getSecurityEventPublisher();
    }

}