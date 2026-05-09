package org.tinycloud.security.session;

import org.tinycloud.security.context.LoginSubject;

/**
 * 会话仓储接口
 *
 * @author liuxingyu01
 * @since 2026-04-28
 */
public interface SessionRepository {

    /**
     * 创建会话
     *
     * @param subject              登录主体
     * @param timeoutSeconds       会话超时时间（秒）
     * @param maxConcurrentLogins  最大并发登录数（<=0 表示不限制）
     * @return 是否创建成功
     */
    boolean save(LoginSubject subject, int timeoutSeconds, int maxConcurrentLogins);

    /**
     * 通过凭证检查会话是否有效
     *
     * @param credentials 会话凭证
     * @return true有效，false无效
     */
    boolean checkByCredentials(String credentials);

    /**
     * 通过凭证获取登录主体
     *
     * @param credentials 会话凭证
     * @return 登录主体
     */
    LoginSubject getSubject(String credentials);

    /**
     * 刷新会话
     *
     * @param credentials 会话凭证
     * @param subject        登录主体
     * @param timeoutSeconds 会话超时时间（秒）
     * @return 是否刷新成功
     */
    boolean refreshByCredentials(String credentials, LoginSubject subject, int timeoutSeconds);

    /**
     * 删除指定凭证会话
     *
     * @param credentials 会话凭证
     * @return 是否删除成功
     */
    boolean deleteByCredentials(String credentials);

    /**
     * 删除指定账号下的全部会话
     *
     * @param loginId 账号ID
     * @return 是否删除成功
     */
    boolean deleteByLoginId(Object loginId);

    /**
     * 统计账号有效在线会话数
     *
     * @param loginId 账号ID
     * @return 有效在线会话数
     */
    int countValidOnlineSessions(Object loginId);
}
