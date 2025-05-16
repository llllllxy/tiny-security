package org.tinycloud.security.provider;


import org.springframework.util.StringUtils;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.AuthUtil;
import org.tinycloud.security.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;

/**
 * 操作token和会话的接口
 *
 * @author liuxingyu01
 * @version 2023-01-06-9:33
 **/
public interface AuthProvider {

    /*============================操作token开始=============================*/

    /**
     * 获取当前会话的token值（jwtToken）
     *
     * @param request HttpServletRequest
     * @return String
     */
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

    /**
     * 获取当前会话的token值（jwtToken）
     *
     * @return String
     */
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
     * 根据token值（jwtToken）解析得到会话凭证（redis、database、memory里面的key）
     *
     * @param token jwtToken
     * @return 会话凭证
     */
    default String getCredentialsByToken(String token) {
        // 校验token是不是伪造的
        Map<String, String> claims = JwtUtil.getClaims(GlobalConfigUtils.getGlobalConfig().getJwtSecret(), token);
        if (Objects.isNull(claims)) {
            throw new UnAuthorizedException();
        }
        // 从jwt的Payload里获取credentials，这才是会话的凭证key，它在redis或者mysql里面存着用户信息
        return claims.get("credentials");
    }

    /**
     * 根据token值（jwtToken）解析得到会话凭证（redis、database、memory里面的key）
     *
     * @return 会话凭证
     */
    default String getCredentials() {
        String jwtToken = this.getToken();
        return getCredentialsByToken(jwtToken);
    }

    /**
     * 获取获取会话凭证
     *
     * @param request HttpServletRequest
     * @return 会话凭证
     */
    default String getCredentials(HttpServletRequest request) {
        String jwtToken = this.getToken(request);
        return getCredentialsByToken(jwtToken);
    }

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
     * @param request HttpServletRequest
     */
    void logout(HttpServletRequest request);

    /**
     * 获取当前登录用户的loginId
     *
     * @return Object
     */
    Object getLoginId();

    /**
     * 获取当前登录用户的loginId, 并转换为 String 类型
     *
     * @return 账号id
     */
    default String getLoginIdAsString() {
        return String.valueOf(getLoginId());
    }

    /**
     * 获取当前登录用户的loginId, 并转换为 Integer 类型
     *
     * @return 账号id
     */
    default Integer getLoginIdAsInt() {
        return Integer.parseInt(String.valueOf(getLoginId()));
    }

    /**
     * 获取当前登录用户的loginId, 并转换为 Long 类型
     *
     * @return 账号id
     */
    default Long getLoginIdAsLong() {
        return Long.parseLong(String.valueOf(getLoginId()));
    }

    /**
     * 获取当前登录用户信息
     *
     * @return LoginSubject
     */
    LoginSubject getLoginSubject();

    /**
     * 校验当前会话是否登录
     *
     * @return true已登录，false未登录
     */
    boolean isLogin();

    /**
     * 检验当前会话是否已经登录, 如果未登录，则抛出异常
     *
     * @return true已登录，false未登录（会抛出异常）
     */
    boolean checkLogin();
    /*============================操作会话结束=============================*/
}
