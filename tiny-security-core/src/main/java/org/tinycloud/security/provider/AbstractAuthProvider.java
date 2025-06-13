package org.tinycloud.security.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.AuthUtil;
import org.tinycloud.security.util.CookieUtil;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;

public abstract class AbstractAuthProvider implements AuthProvider {
    private final static Logger log = LoggerFactory.getLogger(AbstractAuthProvider.class);

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     */
    @Override
    public String login(Object loginId, Map<String, Object> extraInfo) {
        String token = this.createAuth(loginId, extraInfo);
        // 设置 Cookie，通过 Cookie 上下文返回给前端
        CookieUtil.setCookie(AuthUtil.getResponse(), GlobalConfigUtils.getGlobalConfig().getTokenName(), token);
        return token;
    }

    /**
     * 退出登录
     */
    @Override
    public void logout(HttpServletRequest request) {
        this.deleteByCredentials(this.getCredentials(request));
    }

    /**
     * 退出登录
     */
    @Override
    public void logout() {
        this.deleteByCredentials(this.getCredentials());
    }

    /**
     * 获取当前登录用户的loginId（未登录时会抛出异常）
     *
     * @return loginId
     */
    @Override
    public Object getLoginId() {
        return this.getLoginSubject().getLoginId();
    }

    /**
     * 获取当前登录用户信息（未登录时会抛出异常）
     *
     * @return LoginSubject
     */
    @Override
    public LoginSubject getLoginSubject() {
        LoginSubject subject = this.getSubject(this.getCredentials());
        if (Objects.isNull(subject)) {
            throw new UnAuthorizedException();
        }
        return subject;
    }

    /**
     * 校验当前会话是否登录
     *
     * @return true已登录，false未登录（不抛出异常）
     */
    @Override
    public boolean isLogin() {
        try {
            return this.checkByCredentials(this.getCredentials());
        } catch (Exception e) {
            log.error("AbstractAuthProvider isLogin failed, Exception：{e}", e);
            return false;
        }
    }

    /**
     * 校验当前会话是否登录（未登录时会抛出异常）
     *
     * @return true已登录，false未登录
     */
    @Override
    public boolean checkLogin() {
        boolean success = this.checkByCredentials(this.getCredentials());
        if (!success) {
            throw new UnAuthorizedException();
        }
        return true;
    }
}
