package org.tinycloud.security.provider;


import org.springframework.util.StringUtils;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.AuthUtil;

import javax.servlet.http.HttpServletRequest;

/**
 * 操作token和会话的接口
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public interface AuthProvider {

    /*============================操作token开始=============================*/

    default String getToken(HttpServletRequest request) {
        String jwtToken = AuthUtil.getToken(request, GlobalConfigUtils.getGlobalConfig().getTokenName());
        // 第1步：先判断jwtToken是否为空
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        // 第2步：校验token的格式是否正确
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            // 去除TOKEN_PREFIX
            jwtToken = jwtToken.replace(AuthConsts.JWT_TOKEN_PREFIX, "");
        } else { // token不是以TOKEN_PREFIX开头的，不合格
            throw new UnAuthorizedException();
        }
        return jwtToken;
    }

    default String getToken() {
        String jwtToken = AuthUtil.getToken(GlobalConfigUtils.getGlobalConfig().getTokenName());
        // 第1步：先判断jwtToken是否为空
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        // 第2步：校验token的格式是否正确
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            // 去除TOKEN_PREFIX
            jwtToken = jwtToken.replace(AuthConsts.JWT_TOKEN_PREFIX, "");
        } else { // token不是以TOKEN_PREFIX开头的，不合格
            throw new UnAuthorizedException();
        }
        return jwtToken;
    }

    /**
     * 获取会话凭证
     *
     * @return 会话凭证
     */
    String getCredentials();

    /**
     * 获取获取会话凭证
     *
     * @param request HttpServletRequest
     * @return 会话凭证
     */
    String getCredentials(HttpServletRequest request);

    /**
     * 刷新credentials
     *
     * @param credentials
     * @return
     */
    boolean refreshByCredentials(String credentials);

    /**
     * 刷新credentials，并且重置用户
     *
     * @param credentials
     * @return
     */
    boolean refreshByCredentials(String credentials, LoginSubject subject);

    /**
     * 检查credentials是否失效
     *
     * @param credentials
     * @return
     */
    boolean checkByCredentials(String credentials);

    /**
     * 获取登录用户信息
     *
     * @param credentials
     * @return
     */
    LoginSubject getSubject(String credentials);

    /**
     * 创建一个新的token
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return
     */
    String createAuth(Object loginId);

    /**
     * 删除会话（根据token）
     *
     * @param token
     * @return
     */
    boolean deleteByToken(String token);

    /**
     * 删除会话（根据凭证）
     *
     * @param credentials
     * @return
     */
    boolean deleteByCredentials(String credentials);

    /**
     * 通过loginId删除token---常用于主动让某人下线
     *
     * @param loginId
     * @return
     */
    boolean deleteByLoginId(Object loginId);

    /*============================操作token结束=============================*/


    /*============================操作会话开始，此部分在AbstractAuthProvider里予以实现=============================*/

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     */
    String login(Object loginId);

    /**
     * 退出登录
     */
    void logout();

    /**
     * HttpServletRequest request
     *
     * @param request
     */
    void logout(HttpServletRequest request);

    /**
     * 获取当前登录用户的loginId
     *
     * @return
     */
    Object getLoginId();

    /**
     * 获取当前登录用户信息
     *
     * @return
     */
    LoginSubject getLoginSubject();

    /**
     * 校验当前会话是否登录
     *
     * @return true已登录，false未登录
     */
    boolean isLogin();
    /*============================操作会话结束=============================*/
}
