package org.tinycloud.security.provider;

import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.util.AuthUtil;
import org.tinycloud.security.util.CookieUtil;

import javax.servlet.http.HttpServletRequest;

public abstract class AbstractAuthProvider implements AuthProvider {

    /**
     * 获取token
     * @return token
     */
    @Override
    public String getToken() {
        String token = AuthUtil.getToken(GlobalConfigUtils.getGlobalConfig().getTokenName());
        return token;
    }

    /**
     * 获取token
     * @param request HttpServletRequest
     * @return token
     */
    @Override
    public String getToken(HttpServletRequest request) {
        String token = AuthUtil.getToken(request, GlobalConfigUtils.getGlobalConfig().getTokenName());
        return token;
    }

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     */
    @Override
    public String login(Object loginId) {
        String token = this.createToken(loginId);
        // 设置 Cookie，通过 Cookie 上下文返回给前端
        CookieUtil.setCookie(AuthUtil.getResponse(), GlobalConfigUtils.getGlobalConfig().getTokenName(), token);
        return token;
    }

    /**
     * 退出登录
     */
    @Override
    public void logout(HttpServletRequest request) {
        this.deleteToken(this.getToken(request));
    }

    /**
     * 退出登录
     */
    @Override
    public void logout() {
        this.deleteToken(this.getToken());
    }

    /**
     * 获取当前登录用户的loginId
     *
     * @return loginId
     */
    @Override
    public Object getLoginId() {
        return this.getLoginId(this.getToken());
    }

    /**
     * 校验当前会话是否登录
     * @return true已登录，false未登录
     */
    @Override
    public boolean isLogin() {
        return this.checkToken(this.getToken());
    }
}
