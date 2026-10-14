package org.tinycloud.security.context;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;

/**
 * <p>
 *     登录主体，包含登录账号id、登录凭证等信息
 * </p>
 *
 * <p><b>1.5.0 · 滚动发布安全</b>：会话是以 JSON 存在 Redis / JDBC 里的，而滚动发布期间新旧实例会并存，
 * 新实例写下的会话里可能带着旧实例不认识的字段。这里显式忽略未知字段——否则 Jackson 默认的
 * {@code FAIL_ON_UNKNOWN_PROPERTIES} 会让旧实例反序列化失败，{@code readValue} 返回 null，
 * 被上层当成"会话不存在"而把所有在线用户打成 401。
 *
 * <p>因此本类<b>只应增字段，不应改名或删除字段</b>；改字段语义时请按"新增字段 + 兼容旧字段"的方式演进。
 *
 * <p><b>1.5.0 · loginId 类型契约（P1-9）</b>：{@link #loginId} 声明为 {@code Object}，但 JSON 往返会让
 * 数值类型漂移 —— {@code Long 10001} 序列化后是 {@code 10001}，反序列化默认给回 {@code Integer}，
 * 于是 {@code (Long) subject.getLoginId()} 抛 {@code ClassCastException}。为了让四个仓储的
 * {@code getSubject} 行为一致（内存版存引用、Redis/JDBC 走 JSON），这里在**反序列化时统一归一化**：
 * <ul>
 *     <li>整型数值一律归一化为 {@link Long}（小数保持原样，避免有损转换）；</li>
 *     <li>字符串保持字符串（不做"看起来像数字就转 Long"的猜测，避免改变既有语义）。</li>
 * </ul>
 * 归一化发生在 {@link #setLoginId(Object)}，因此**直接 set 与 JSON 往返得到同一类型**，见
 * {@code SessionRepositoryContractTest}。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginSubject implements Serializable {
    @Serial
    private static final long serialVersionUID = -1L;

    /**
     * 登录账号ID
     */
    private Object loginId;

    /**
     * 扩展信息
     */
    private Map<String, Object> extraInfo;

    /**
     * 登录时间
     */
    private Long loginTime;

    /**
     * 登录过期时间
     */
    private Long loginExpireTime;

     /**
      * 登录凭证
      */
     private String credentials;

    public Object getLoginId() {
        return loginId;
    }

    /**
     * 设置登录账号ID。
     *
     * <p>JSON 反序列化同样走这里，因此在此归一化整型类型：{@code Integer} → {@code Long}，
     * 保证"直接构造"与"JSON 往返"得到同一类型（P1-9）。
     */
    @JsonSetter("loginId")
    public void setLoginId(Object loginId) {
        this.loginId = normalizeLoginId(loginId);
    }

    /**
     * 归一化 loginId 的数值类型。
     *
     * <p>只处理整型（{@code Integer}/{@code Short}/{@code Byte} → {@code Long}）；
     * {@code Long} 原样返回，其它类型（含 {@code Double}、{@code String}）不变，
     * 避免引入有损转换或改变既有语义。
     *
     * @param loginId 原始值
     * @return 归一化后的值
     */
    private static Object normalizeLoginId(Object loginId) {
        if (loginId instanceof Integer || loginId instanceof Short || loginId instanceof Byte) {
            return ((Number) loginId).longValue();
        }
        return loginId;
    }

    /**
     * 复制一份登录主体（浅拷贝）。
     *
     * <p><b>为什么需要它</b>：{@code single} / {@code caffeine} 仓储把对象**引用**存在内存里，
     * 而 {@code redis} / {@code jdbc} 仓储每次读出来都是 JSON 反序列化的**新对象**。若不复制，
     * 同样一份用户代码在四种仓储下语义不同 —— 例如调用方修改读到的 subject（如
     * {@code setLoginExpireTime(...)}），在内存版会**直接改写缓存中的共享实例**并在后续请求中生效，
     * 在 Redis/JDBC 版则不会（P1-9）。返回副本后四种仓储行为一致。
     *
     * <p>浅拷贝即可：{@code extraInfo} 不深拷贝，因为四种仓储对它的处理本就不同（内存版共享、
     * Redis/JDBC 版每次反序列化重建），深拷贝无法改变这一事实，反而增加开销。当前框架内部
     * 不会修改 {@code extraInfo}，调用方若需要修改请自行复制后再 set。
     *
     * @return 副本；{@code this} 为 null 时返回 null
     */
    public LoginSubject copy() {
        LoginSubject copy = new LoginSubject();
        copy.loginId = this.loginId;
        copy.extraInfo = this.extraInfo;
        copy.loginTime = this.loginTime;
        copy.loginExpireTime = this.loginExpireTime;
        copy.credentials = this.credentials;
        return copy;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }

    public Long getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(Long loginTime) {
        this.loginTime = loginTime;
    }

    public Long getLoginExpireTime() {
        return loginExpireTime;
    }

    public void setLoginExpireTime(Long loginExpireTime) {
        this.loginExpireTime = loginExpireTime;
    }

     public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    @Override
    public String toString() {
        // credentials 为会话凭证，输出到日志会造成泄露，这里固定脱敏
        return "LoginSubject{" +
                "loginId=" + loginId +
                ", extraInfo=" + extraInfo +
                ", loginTime=" + loginTime +
                ", loginExpireTime=" + loginExpireTime +
                ", credentials=" + "****" +
                '}';
    }
}
