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
     * @param maxConcurrentLogins  最大并发登录数（{@code <=0} 表示不限制）
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

    /**
     * 获取全部在线账号ID（去重，一个账号多端登录只算一个）。
     *
     * <p>典型用途：运维后台的「在线用户」列表、全量在线人数统计。与
     * {@link #getCredentialsByLoginId(Object)}（单账号的全部会话）互补 —— 后者回答
     * "某个人在哪些设备上在线"，本方法回答"现在一共有谁在线"。
     *
     * <p><b>返回元素的实际类型是 {@link String}</b>：jdbc/redis 存的就是 varchar 列 / Redis key 后缀，
     * 内存版（single / caffeine）也统一 {@code String.valueOf(loginId)} 后返回，
     * 避免同一份代码切换 {@code store-type} 后拿到的 loginId 类型漂移。
     * 调用方需要数值时请自行转换（如 {@code Long.valueOf(String.valueOf(loginId))}）。
     *
     * <p><b>实现成本与存储强相关（重要）</b>：本方法是"全局维度"的查询，而四种仓储的全局索引能力差异很大：
     * <ul>
     *     <li>{@code jdbc}：一条 {@code SELECT DISTINCT login_id ... WHERE credentials_expire_time > ?}，
     *         可走索引，成本最低；</li>
     *     <li>{@code single} / {@code caffeine}：遍历本地内存 Map 的 keySet，O(账号数) 纯内存操作；
     *         <b>多实例部署下只能看到本实例</b>；</li>
     *     <li>{@code redis}：没有任何全局结构，只能 {@code SCAN} 在线列表 key 前缀
     *         （{@code tiny:security:online:*}）。这不是 {@code KEYS}（会阻塞 Redis），
     *         但仍是 <b>O(全库 key 数)</b> 的遍历 —— 详见 {@code RedisSessionRepository} 的实现注释。</li>
     * </ul>
     * 因此本方法<b>不适合高频调用</b>（如每次请求都调、或放进轮询接口）。
     *
     * <p><b>默认实现抛 {@link UnsupportedOperationException}</b>：内置四种仓储均已实现；自定义仓储若未重写，
     * 说明该存储不支持全局查询，调用时明确报错而非静默返回空列表（与
     * {@link #getCredentialsByLoginId(Object)} 一致的策略，且同样用 default 保持编译兼容）。
     *
     * @return 当前存在有效会话的账号ID列表（去重）；无在线账号时返回空列表（<b>不返回 null</b>）
     * @throws UnsupportedOperationException 仓储未实现该方法时抛出
     */
    default List<Object> getOnlineLoginIds() {
        throw new UnsupportedOperationException(
                "getOnlineLoginIds is not supported by " + this.getClass().getName());
    }

    /**
     * 统计在线账号数（去重，与 {@link #countValidOnlineSessions(Object)} 的"会话数"是两个口径）。
     *
     * <p>一个账号在 3 台设备登录：本方法返回 {@code 1}（在线"人"数），而三个账号各自的
     * {@code countValidOnlineSessions} 之和为 {@code 3}（在线"会话"数）。
     * 报表里"当前在线人数"要的是前者，"当前活跃会话数"要的是后者，请勿混用。
     *
     * <p><b>默认实现为 {@code getOnlineLoginIds().size()}</b>：正确但要把全量账号拉回来再计数。
     * 内置仓储中 jdbc 已覆写为 {@code COUNT(DISTINCT login_id)} 下推到数据库执行，
     * 其余三个仓储直接沿用默认实现（它们的 {@link #getOnlineLoginIds()} 本就是内存/遍历操作，
     * 没有更省的下推方式）。自定义仓储若能用一条命令完成计数，建议覆写本方法。
     *
     * <p>性能注意事项与 {@link #getOnlineLoginIds()} 完全相同（同样是全局查询），
     * 且默认实现会拉取全量账号列表，开销不低于 {@link #getOnlineLoginIds()}。
     *
     * @return 在线账号数；无人在线时返回 0
     * @throws UnsupportedOperationException 仓储未实现 {@link #getOnlineLoginIds()} 时抛出
     */
    default int countOnlineUsers() {
        return this.getOnlineLoginIds().size();
    }
}
