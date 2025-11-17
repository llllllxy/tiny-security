package org.tinycloud.security.provider;


import org.springframework.util.StringUtils;
import org.tinycloud.security.config.GlobalConfigUtils;
import org.tinycloud.security.consts.AuthConsts;
import org.tinycloud.security.exception.UnAuthorizedException;
import org.tinycloud.security.util.AuthUtil;
import org.tinycloud.security.util.JwtUtil;

import javax.servlet.http.HttpServletRequest;
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
     * @throws UnAuthorizedException 获取不到时抛出UnAuthorizedException异常
     */
    default String getToken(HttpServletRequest request) {
        String jwtToken = AuthUtil.getToken(request, GlobalConfigUtils.getGlobalConfig().getTokenName());
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            jwtToken = jwtToken.replace(AuthConsts.JWT_TOKEN_PREFIX, "");
        } else {
            throw new UnAuthorizedException();
        }
        return jwtToken;
    }

    /**
     * 获取当前会话的token值（jwtToken）
     *
     * @return String
     * @throws UnAuthorizedException 获取不到时抛出UnAuthorizedException异常
     */
    default String getToken() {
        String jwtToken = AuthUtil.getToken(GlobalConfigUtils.getGlobalConfig().getTokenName());
        if (!StringUtils.hasText(jwtToken)) {
            throw new UnAuthorizedException();
        }
        if (jwtToken.startsWith(AuthConsts.JWT_TOKEN_PREFIX)) {
            jwtToken = jwtToken.replace(AuthConsts.JWT_TOKEN_PREFIX, "");
        } else {
            throw new UnAuthorizedException();
        }
        return jwtToken;
    }

    /**
     * 根据token值（jwtToken）解析得到会话凭证（redis、database、memory里面的key）
     *
     * @param token jwtToken
     * @return 会话凭证
     * @throws UnAuthorizedException 校验jwtToken失败时抛出UnAuthorizedException异常
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
     * @throws UnAuthorizedException 校验jwtToken失败时抛出UnAuthorizedException异常
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
     * @throws UnAuthorizedException 校验jwtToken失败时抛出UnAuthorizedException异常
     */
    default String getCredentials(HttpServletRequest request) {
        String jwtToken = this.getToken(request);
        return getCredentialsByToken(jwtToken);
    }

    /**
     * 刷新credentials（不抛出异常）
     *
     * @param credentials 会话凭证
     * @return 是否刷新成功，true刷新成功，false刷新失败
     */
    boolean refreshByCredentials(String credentials);

    /**
     * 刷新credentials，并且重置用户信息（不抛出异常）
     *
     * @param credentials 会话凭证
     * @param subject     登录用户信息
     * @return 是否刷新成功，true刷新成功，false刷新失败
     */
    boolean refreshByCredentials(String credentials, LoginSubject subject);

    /**
     * 检查credentials是否失效，true未失效，false已失效（不抛出异常）
     *
     * @param credentials 会话凭证
     * @return 是否失效，true未失效，false已失效
     */
    boolean checkByCredentials(String credentials);

    /**
     * 获取登录用户信息，（不抛出异常）
     *
     * @param credentials 会话凭证
     * @return 登录用户信息，失效或获取失败时返回null
     */
    LoginSubject getSubject(String credentials);

    /**
     * 创建一个新的token
     *
     * @param loginId   会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @param extraInfo 额外的扩展信息，更灵活
     * @return jwtToken， 创建失败时返回null
     */
    String createAuth(Object loginId, Map<String, Object> extraInfo);

    /**
     * 删除会话（根据token），（不抛出异常）
     *
     * @param token jwtToken
     * @return 是否删除成功，true删除成功，false删除失败
     */
    boolean deleteByToken(String token);

    /**
     * 删除会话（根据凭证），（不抛出异常）
     *
     * @param credentials 会话凭证
     * @return 是否删除成功，true删除成功，false删除失败
     */
    boolean deleteByCredentials(String credentials);

    /**
     * 删除会话（根据loginId）常用于主动让某人下线（不抛出异常）
     *
     * @param loginId 账号id
     * @return 是否删除成功，true删除成功，false删除失败
     */
    boolean deleteByLoginId(Object loginId);

    /*============================操作token结束=============================*/


    /*============================操作会话开始，此部分在AbstractAuthProvider里予以实现=============================*/

    /**
     * 执行登录操作
     *
     * @param loginId 会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @return jwtToken
     */
    default String login(Object loginId) {
        return login(loginId, null);
    }

    /**
     * 执行登录操作
     *
     * @param loginId   会话登录：参数填写要登录的账号id，建议的数据类型：long | int | String， 不可以传入复杂类型，如：User、Admin 等等
     * @param extraInfo 额外的扩展信息，更灵活
     * @return jwtToken
     */
    String login(Object loginId, Map<String, Object> extraInfo);

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
     * 获取当前登录用户信息，如果未登录，则抛出异常
     *
     * @return LoginSubject
     */
    LoginSubject getLoginSubject();

    /**
     * 校验当前会话是否登录（不抛出异常）
     *
     * @return true已登录，false未登录
     */
    boolean isLogin();

    /**
     * 检验当前会话是否已经登录，如果未登录，则抛出异常
     *
     * @return true已登录，未登录抛出UnAuthorizedException异常
     * @throws UnAuthorizedException 未登录抛出UnAuthorizedException异常
     */
    boolean checkLogin();
    /*============================操作会话结束=============================*/
}
