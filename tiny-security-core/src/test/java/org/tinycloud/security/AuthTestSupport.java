package org.tinycloud.security;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.tinycloud.security.provider.AuthProvider;

/**
 * 测试辅助：搭建 {@link org.tinycloud.security.util.AuthUtil} 所需的 Web 环境。
 *
 * <p>1.5.0 起 {@code AuthUtil} 通过「当前请求 → ServletContext → WebApplicationContext →
 * getBean(AuthProvider)」解析实例门面（不再有可变静态全局变量），因此凡是走 {@code AuthUtil}
 * 的用例都需要这样一套环境。这里复刻的正是 Spring 在真实 Web 应用中的装配方式
 * （{@code ServletWebServerApplicationContext} 会把自身写入 ServletContext 的 ROOT 属性）。
 *
 * @author liuxingyu01
 * @since 2026-08-08
 */
public final class AuthTestSupport {

    private AuthTestSupport() {
    }

    /**
     * 把 AuthProvider 注册进一个 WebApplicationContext，挂到 ServletContext 上，并绑定到当前线程。
     *
     * @param authProviders 要暴露给 AuthUtil 的实例门面；传多个可覆盖「候选 Bean 不唯一」的报错路径
     * @return 绑定到当前线程的请求
     */
    public static MockHttpServletRequest bindRequestWithAuthProvider(AuthProvider... authProviders) {
        GenericWebApplicationContext applicationContext = new GenericWebApplicationContext();
        for (int i = 0; i < authProviders.length; i++) {
            applicationContext.getBeanFactory().registerSingleton("authProvider" + i, authProviders[i]);
        }
        applicationContext.refresh();
        return bindRequest(applicationContext);
    }

    /**
     * 绑定一个「有请求、但没有 WebApplicationContext」的请求，用于验证配置错误路径。
     *
     * @return 绑定到当前线程的请求
     */
    public static MockHttpServletRequest bindRequestWithoutApplicationContext() {
        return bindRequest(null);
    }

    /**
     * 绑定一个「有请求、有 WebApplicationContext、但其中没有 AuthProvider Bean」的请求。
     *
     * @return 绑定到当前线程的请求
     */
    public static MockHttpServletRequest bindRequestWithoutAuthProviderBean() {
        GenericWebApplicationContext applicationContext = new GenericWebApplicationContext();
        applicationContext.refresh();
        return bindRequest(applicationContext);
    }

    private static MockHttpServletRequest bindRequest(WebApplicationContext applicationContext) {
        MockServletContext servletContext = new MockServletContext();
        if (applicationContext != null) {
            servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE,
                    applicationContext);
        }
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        return request;
    }
}
