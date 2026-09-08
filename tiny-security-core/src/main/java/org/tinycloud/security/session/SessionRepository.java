package org.tinycloud.security.session;

import org.tinycloud.security.context.LoginSubject;

import java.util.List;

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

    /**
     * 获取指定账号下全部有效（未过期）会话凭证。
     *
     * <p>典型用途：
     * <ul>
     *     <li>多设备管理：列出账号当前所有在线会话（设备）</li>
     *     <li>定向下线：配合 {@link #deleteByCredentials(String)} 只踢掉指定凭证，
     *         而非 {@link #deleteByLoginId(Object)} 的全量踢出</li>
     * </ul>
     *
     * <p><b>默认实现抛 {@link UnsupportedOperationException}</b>：本方法依赖"账号 → 凭证列表"
     * 的反向索引，内置四种仓储（single / caffeine / redis / jdbc）均已实现；自定义仓储若未重写，
     * 说明该存储不支持按账号反查凭证，调用时将明确报错而非静默返回空列表。
     * 之所以用 default 而非抽象方法，是为了不破坏升级前已有的自定义仓储实现（保持编译兼容）。
     *
     * @param loginId 账号ID
     * @return 该账号的有效会话凭证列表；无有效会话时返回空列表（<b>不返回 null</b>）
     * @throws UnsupportedOperationException 仓储未实现该方法时抛出
     */
    default List<String> getCredentialsByLoginId(Object loginId) {
        throw new UnsupportedOperationException(
                "getCredentialsByLoginId is not supported by " + this.getClass().getName());
    }
}
