# tiny-security 2.0 设计稿

## 1. 背景

`tiny-security` 当前已经具备以下基础能力：

- 登录态创建与注销
- 基于 JWT 的 token 承载
- 基于内存 / Redis / JDBC 的会话存储
- 基于注解和 URL 的权限校验
- 简单的并发登录限制
- Spring Boot 自动装配

从当前实现看，项目定位更接近“轻量安全组件”，而不是“完整安全框架”。如果希望它进一步完善，并参考 Shiro、Spring Security 等成熟框架的能力，`2.0` 需要从“功能叠加”转向“架构升级”。

`2.0` 的核心目标不是简单多几个注解，而是建立一套：

- 安全默认值可靠
- 扩展点边界清晰
- Spring 生态集成自然
- 多存储实现行为一致
- 后续可持续演进

的框架基础设施。

---

## 2. 现状评估

### 2.1 当前优点

- 接入成本低，主链路短，适合小项目快速落地
- `AuthProvider` facade 保持了“登录态操作”的统一入口，用户上手直观
- 已经具备多存储实现，说明框架有抽象雏形
- 注解式权限校验对于业务方比较友好
- starter + core 双模块结构是合理起点

### 2.2 当前主要问题

#### 1. 抽象层次偏粗

在历史实现中，`AuthProvider` 同时承担了：

- token 解析
- token 签发
- 会话存储
- 登录态查询
- 并发登录控制
- 刷新策略

这会导致：

- 一个接口职责过重
- 新增能力容易互相耦合
- 不同实现之间难以保持一致行为

#### 2. 安全默认值偏弱

当前存在一些不适合作为框架默认值的点：

- JWT secret 可缺省且带固定默认值
- Cookie 缺少 `Secure`、`SameSite`、`Domain` 等可控项
- logout 未完整清理 Cookie
- token 生命周期与会话生命周期没有完全解耦表达

#### 3. Spring 集成还停留在“能用”

目前主要通过 MVC `HandlerInterceptor` 工作，具备基本能力，但距离成熟框架还有差距：

- 过滤链 / 认证链不可组合
- 拦截器直接 `new`，不利于 Bean 覆盖
- 异常响应未形成统一扩展点
- 方法级鉴权没有表达式能力
- 缺少面向 Spring 的事件和上下文桥接

#### 4. 存储实现行为不完全一致

不同存储下并发登录控制、清理策略、过期策略和异常语义不完全统一，后续会逐渐演变成维护负担。

#### 5. 工程化能力不足

- README 编码与内容存在不一致
- 缺少系统化测试矩阵
- 缺少基准和兼容性约束
- 缺少清晰版本演进策略

---

## 3. 2.0 定位

### 3.1 产品定位

`tiny-security 2.0` 的定位建议定义为：

> 一个面向 Spring Boot Web 场景的、轻量但可扩展的认证与授权框架。

它不是直接复刻 Spring Security，也不应与其正面对齐所有特性，而应坚持：

- 比 Spring Security 更轻
- 比 Shiro 在 Spring Boot 场景中更现代
- 比单纯工具包更体系化

### 3.2 目标用户

- 中小型 Spring Boot 项目
- 希望快速接入权限框架，但不想引入 Spring Security 全家桶的团队
- 有一定定制需求，希望保留扩展能力的业务系统
- 内部中台、管理后台、SaaS 业务平台

### 3.3 非目标

`2.0` 第一阶段不追求：

- OAuth2 授权服务器全套能力
- SAML / CAS 等重型协议支持
- 全量替代 Spring Security
- 响应式与 Servlet 同时一步到位

---

## 4. 设计原则

### 4.1 安全优先于便捷

框架默认值必须尽量安全，宁可多一点配置，也不能让用户在不知情时落入危险默认值。

### 4.2 核心链路简洁

普通用户接入时仍要尽量保持：

- 引 starter
- 配几项参数
- 调用 login/logout
- 注解鉴权

即可完成接入。

### 4.3 抽象分层清晰

把“令牌”“会话”“鉴权”“异常处理”“并发控制”“上下文”拆开，避免一个接口包办全部职责。

### 4.4 扩展点先于功能点

在框架建设期，优先设计 SPI，而不是先堆一批注解。只有扩展点清楚，功能才能持续增长而不失控。

### 4.5 兼容优先、渐进升级

`2.0` 应支持从 `1.x` 平滑迁移，避免一次性破坏式重写。

---

## 5. 总体架构

建议将 `2.0` 架构拆为以下层次：

```text
tiny-security
├─ tiny-security-core
│  ├─ context
│  ├─ token
│  ├─ session
│  ├─ authc
│  ├─ authz
│  ├─ event
│  ├─ exception
│  └─ spi
├─ tiny-security-web
│  ├─ servlet filter / interceptor
│  ├─ request token resolver
│  ├─ cookie support
│  ├─ mvc exception bridge
│  └─ annotation support
├─ tiny-security-spring-boot-starter
│  ├─ auto-configuration
│  ├─ properties binding
│  ├─ bean conditions
│  └─ defaults
├─ tiny-security-storage-memory
├─ tiny-security-storage-redis
├─ tiny-security-storage-jdbc
└─ tiny-security-test-support
```

### 5.1 模块调整建议

当前 starter / core 两层还不够。建议拆成：

- `tiny-security-core`
  - 只放抽象、模型、默认实现、异常、SPI
- `tiny-security-web`
  - 放 Web 场景能力，不把 servlet 依赖污染全部 core
- `tiny-security-spring-boot-starter`
  - 自动装配
- `tiny-security-storage-*`
  - 每种存储独立模块，降低 starter 的条件复杂度
- `tiny-security-test-support`
  - 供集成测试、示例工程和下游使用

这样会比当前结构更利于长期演进。

---

## 6. 核心概念模型

### 6.1 Subject

建议保留 `LoginSubject` 的思路，但升级为更明确的主体模型：

```java
public interface SecuritySubject {
    Serializable getPrincipal();
    String getSessionId();
    String getTokenId();
    Instant getLoginTime();
    Instant getExpireAt();
    Map<String, Object> getAttributes();
}
```

建议：

- `principal` 表达身份主体，如 userId
- `attributes` 只作为扩展字段
- 避免把所有语义都塞到 `extraInfo`

默认实现可以叫 `DefaultSecuritySubject`。

### 6.2 Session

建议把“登录主体”和“会话”区分开：

```java
public interface SecuritySession {
    String getSessionId();
    Serializable getPrincipal();
    Instant getCreateTime();
    Instant getLastAccessTime();
    Instant getExpireAt();
    String getDevice();
    String getClientIp();
    Map<String, Object> getAttributes();
}
```

理由：

- 一个用户可能有多个 session
- 并发登录控制本质上是 session 管理
- 后续踢人下线、设备维度登录都依赖 session 模型

### 6.3 Token

建议明确 token 只负责“承载引用或声明”，不要与 session 存储强耦合：

```java
public interface SecurityToken {
    String getValue();
    String getTokenType();
    String getTokenId();
    Instant getIssuedAt();
    Instant getExpireAt();
}
```

---

## 7. 核心 SPI 设计

这是 `2.0` 最重要的部分。

### 7.1 TokenResolver

负责从请求中提取 token。

```java
public interface TokenResolver {
    String resolve(HttpServletRequest request);
}
```

默认支持：

- Header
- Cookie
- Query Param

并允许按顺序组合多个 resolver。

对应 Shiro / Spring Security 的参考点：

- 类似 Spring Security 中不同 authentication converter / resolver 的思想

### 7.2 TokenSigner

负责签发与校验 token。

```java
public interface TokenSigner {
    String sign(TokenClaims claims);
    TokenClaims verify(String token);
}
```

默认实现：

- `JwtTokenSigner`

后续可扩展：

- opaque token
- 自定义 HMAC / RSA / SM 系列算法
- 密钥轮换

### 7.3 SessionStore

负责会话持久化。

```java
public interface SessionStore {
    void save(SecuritySession session);
    SecuritySession get(String sessionId);
    void delete(String sessionId);
    void refresh(String sessionId, Instant expireAt);
    List<SecuritySession> listByPrincipal(Serializable principal);
}
```

默认实现：

- `InMemorySessionStore`
- `RedisSessionStore`
- `JdbcSessionStore`

### 7.4 AuthenticationManager

负责“建立登录态”和“校验当前登录态”。

```java
public interface AuthenticationManager {
    LoginResult login(LoginRequest request);
    void logout(LogoutRequest request);
    Authentication authenticate(AuthenticationToken token);
}
```

这里建议把“用户密码是否正确”与“框架创建会话”分开：

- 业务系统仍自己校验用户名密码
- 框架负责建立安全上下文

后续如果要增强，可引入 `CredentialVerifier`。

### 7.5 AuthorizationManager

负责权限和角色判断。

```java
public interface AuthorizationManager {
    boolean hasRole(SecuritySubject subject, String role);
    boolean hasPermission(SecuritySubject subject, String permission);
    AuthorizationDecision check(SecuritySubject subject, AuthorizationRequirement requirement);
}
```

### 7.6 AuthorizationInfoProvider

这是当前 `AuthorizationInfoGet` 的升级版。

```java
public interface AuthorizationInfoProvider {
    Set<String> getRoles(SecuritySubject subject);
    Set<String> getPermissions(SecuritySubject subject);
}
```

增强点：

- 支持缓存装饰器
- 支持失效通知
- 支持多租户上下文

### 7.7 SessionConcurrencyStrategy

把并发登录策略独立出来。

```java
public interface SessionConcurrencyStrategy {
    void onLogin(Serializable principal, String newSessionId);
}
```

可提供几个默认策略：

- `ALLOW`
- `DENY_NEW_LOGIN`
- `KICKOUT_OLDest`
- `KICKOUT_LATEST`

这是对标 Shiro “踢人下线”能力时非常关键的一层。

### 7.8 SecurityContextRepository

负责保存和读取当前请求上下文。

```java
public interface SecurityContextRepository {
    SecurityContext load(HttpServletRequest request);
    void save(SecurityContext context, HttpServletRequest request, HttpServletResponse response);
    void clear(HttpServletRequest request, HttpServletResponse response);
}
```

这会让后续：

- 纯 token 模式
- session + token 混合模式
- remember-me

都能接进来。

### 7.9 EntryPoint / DeniedHandler

对标 Spring Security 中的异常处理机制。

```java
public interface AuthenticationEntryPoint {
    void commence(HttpServletRequest request, HttpServletResponse response, Exception e);
}

public interface AccessDeniedHandler {
    void handle(HttpServletRequest request, HttpServletResponse response, Exception e);
}
```

这样用户就能优雅接入统一 JSON 错误响应。

---

## 8. 请求处理链设计

建议 `2.0` 从“两个 MVC 拦截器”升级为“明确的安全处理链”。

### 8.1 推荐主链路

```text
Request
  -> TokenResolveFilter
  -> AuthenticationFilter
  -> SecurityContextBindFilter
  -> AuthorizationFilter / Method Authorization
  -> Controller
  -> ExceptionTranslation
Response
```

### 8.2 各环节职责

#### TokenResolveFilter

- 从 Header / Cookie / Param 中解析 token
- 解析失败不直接抛业务异常，交给认证层判断

#### AuthenticationFilter

- 校验 token 是否合法
- 加载 session
- 检查是否过期、是否被踢下线
- 必要时刷新 session

#### SecurityContextBindFilter

- 将主体信息放入上下文
- 请求结束清理 ThreadLocal

#### AuthorizationFilter

- URL 维度鉴权
- 适合作为兜底或网关前置策略

#### Method Authorization

- 注解维度鉴权
- 粒度更精确
- 建议逐步改为 AOP 或 Spring 原生 method interceptor

### 8.3 为什么建议引入 Filter

相比只用 MVC Interceptor：

- Filter 更靠近请求入口
- 更适合做认证链与异常翻译
- 更接近 Spring Security 的成熟做法
- 对非 Controller 场景更友好

保留 Interceptor 也可以，但建议定位为补充层，不是核心链。

---

## 9. 鉴权模型设计

### 9.1 鉴权维度

建议 `2.0` 支持 4 类鉴权方式：

- 登录态校验
- 角色校验
- 权限点校验
- 表达式校验

### 9.2 注解体系

建议保留并扩展为：

- `@RequiresLogin`
- `@RequiresGuest`
- `@RequiresRoles`
- `@RequiresPermissions`
- `@RequiresAnyRole`
- `@RequiresAnyPermission`
- `@RequiresAllRoles`
- `@RequiresAllPermissions`
- `@RequiresExpression`

其中：

- 简单场景继续支持现有风格
- 复杂场景再使用表达式

### 9.3 表达式支持

参考 Spring Security，可支持轻量表达式：

```java
@RequiresExpression("hasRole('admin') and hasPermission('user:write')")
```

表达式引擎可以先不做得很重，第一版只支持：

- `hasRole`
- `hasAnyRole`
- `hasPermission`
- `hasAnyPermission`
- `isLogin`
- `isAnonymous`

### 9.4 URL 鉴权

URL 模式建议升级为显式规则模型：

```yaml
tiny-security:
  authz:
    url-rules:
      - pattern: /admin/**
        permissions: [admin:*]
      - pattern: /user/list
        roles: [admin, manager]
        logical: OR
```

不要只靠“路径字符串即权限字符串”的隐式规则，这样更利于维护。

---

## 10. 认证模型设计

### 10.1 建议区分“认证前校验”和“登录态建立”

当前 `login(loginId)` 很轻，但表达力有限。`2.0` 建议改成：

```java
LoginResult login(LoginCommand command)
```

其中 `LoginCommand` 可包含：

- `principal`
- `device`
- `clientIp`
- `rememberMe`
- `attributes`
- `sessionTimeout`

### 10.2 remember-me

建议在 `2.0` 第二阶段支持：

- 短期 access token
- 长期 remember-me token
- remember token 可单独吊销

这块能力非常实用，也能体现与简单 token 工具包的差异。

### 10.3 多端登录

建议引入设备维度：

- `WEB`
- `APP`
- `MINI_PROGRAM`
- `API`

并发控制策略就可以从“一个用户最多 N 个 token”升级为：

- 每设备类型最多 N 个
- 不同设备互不影响

这是很多管理后台和移动端共存项目的真实需求。

---

## 11. 会话与 token 生命周期设计

建议明确分开这几个概念：

- `accessTokenTtl`
- `sessionTtl`
- `refreshThreshold`
- `rememberMeTtl`

### 11.1 推荐语义

- `accessTokenTtl`
  - token 自身有效期
- `sessionTtl`
  - 服务端 session 有效期
- `refreshThreshold`
  - 剩余多久时触发滑动续期

### 11.2 推荐默认策略

- token 和 session 默认同 TTL
- 支持滑动续期
- 支持关闭自动续期

### 11.3 失效原因模型

建议为认证失败建立明确原因枚举：

- `TOKEN_MISSING`
- `TOKEN_INVALID`
- `TOKEN_EXPIRED`
- `SESSION_NOT_FOUND`
- `SESSION_EXPIRED`
- `SESSION_KICKED_OUT`
- `CONCURRENT_LIMIT_EXCEEDED`

这会让异常处理和前端交互更清晰。

---

## 12. Cookie 与前后端场景设计

### 12.1 Cookie 配置项

建议补全：

```yaml
tiny-security:
  cookie:
    enabled: true
    name: token
    path: /
    domain:
    http-only: true
    secure: true
    same-site: LAX
    max-age:
```

### 12.2 Header 配置项

```yaml
tiny-security:
  token:
    header-name: Authorization
    prefix: Bearer
```

### 12.3 前后端分离模式

建议框架明确支持 3 种模式：

- `HEADER_ONLY`
- `COOKIE_ONLY`
- `HEADER_AND_COOKIE`

这样文档表达会比现在更准确。

---

## 13. 缓存与权限加载设计

当前权限接口是每次请求实时查角色/权限。`2.0` 建议加可选缓存层。

### 13.1 缓存抽象

```java
public interface AuthorizationCache {
    AuthorizationInfo get(Serializable principal);
    void put(Serializable principal, AuthorizationInfo info, Duration ttl);
    void evict(Serializable principal);
}
```

### 13.2 使用策略

- 默认不开启
- 开启后支持 TTL
- 支持显式失效

### 13.3 失效触发

例如：

- 用户角色变更
- 用户权限变更
- 用户被禁用

这部分做出来以后，框架就能明显更接近真实生产需求。

---

## 14. 事件机制设计

建议增加事件总线，参考 Spring 事件风格。

### 14.1 事件列表

- `LoginSuccessEvent`
- `LoginFailureEvent`
- `LogoutSuccessEvent`
- `SessionCreatedEvent`
- `SessionExpiredEvent`
- `SessionKickedOutEvent`
- `AuthorizationDeniedEvent`

### 14.2 用途

- 审计日志
- 在线用户统计
- 异常行为监控
- 安全告警

这块是框架从“能用”走向“平台化”的关键一步。

---

## 15. 异常体系设计

建议把异常从笼统类型升级为分层异常。

### 15.1 异常层次

```text
SecurityException
├─ AuthenticationException
│  ├─ TokenMissingException
│  ├─ TokenInvalidException
│  ├─ TokenExpiredException
│  ├─ SessionExpiredException
│  └─ ConcurrentLoginExceededException
└─ AuthorizationException
   ├─ AccessDeniedException
   ├─ MissingRoleException
   └─ MissingPermissionException
```

### 15.2 好处

- 统一映射 HTTP 状态码
- 便于日志分类
- 便于业务方自定义错误码

---

## 16. Spring Boot 自动装配设计

### 16.1 自动装配原则

- 所有默认实现都使用 `@ConditionalOnMissingBean`
- 所有扩展点都允许用户覆盖
- 避免在自动装配中 `new` 关键对象

### 16.2 推荐 Bean 结构

- `TokenResolver`
- `TokenSigner`
- `SessionStore`
- `AuthenticationManager`
- `AuthorizationManager`
- `AuthorizationInfoProvider`
- `AuthenticationEntryPoint`
- `AccessDeniedHandler`
- `SecurityFilter`
- `SecurityProperties`

### 16.3 属性分组建议

建议从扁平配置升级为结构化配置：

```yaml
tiny-security:
  enabled: true
  authc:
    enabled: true
    session-timeout: 1800s
    refresh-threshold: 20%
    max-concurrent-logins: 1
    concurrent-strategy: DENY_NEW_LOGIN
  token:
    type: JWT
    secret: ${TINY_SECURITY_SECRET}
    subject: tiny-security
    header-name: Authorization
    prefix: Bearer
    ttl: 1800s
  cookie:
    enabled: false
    name: token
    path: /
    http-only: true
    secure: true
    same-site: LAX
  authz:
    enabled: true
    mode: ANNOTATION
    cache-enabled: false
    cache-ttl: 300s
  storage:
    type: redis
    table-name: t_auth_storage
```

### 16.4 启动期校验

建议增加配置校验器：

- `JWT` 模式必须配置 secret
- `jdbc` 模式要求可用 `JdbcTemplate`
- `redis` 模式要求可用 `StringRedisTemplate`
- 开启 `authorization` 后若无 `AuthorizationInfoProvider`，启动报错或显式警告

---

## 17. 数据库存储设计

### 17.1 建议表结构升级

当前 JDBC 表建议升级为：

```sql
create table t_auth_session (
  id bigint primary key auto_increment,
  session_id varchar(128) not null unique,
  principal varchar(128) not null,
  token_id varchar(128),
  device varchar(32),
  client_ip varchar(64),
  login_time bigint not null,
  last_access_time bigint not null,
  expire_time bigint not null,
  status varchar(32) not null,
  session_attrs text,
  created_at datetime not null default current_timestamp,
  updated_at datetime not null default current_timestamp on update current_timestamp,
  index idx_principal(principal),
  index idx_expire_time(expire_time),
  index idx_status(status)
);
```

### 17.2 为什么要拆字段

- 更利于查询在线用户
- 更利于踢人下线
- 更利于并发控制
- 更利于统计和审计
- 避免 `login_subject` 一个字段承载全部含义

---

## 18. 在线会话与管理能力

这是很值得做的一组框架功能，Shiro 风格用户会很喜欢。

### 18.1 建议开放 API

```java
public interface SessionManager {
    List<SecuritySession> listSessionsByPrincipal(Serializable principal);
    List<SecuritySession> listActiveSessions();
    void kickout(String sessionId);
    void kickoutByPrincipal(Serializable principal);
    void refresh(String sessionId);
}
```

### 18.2 管理后台价值

可直接支持：

- 在线用户列表
- 强制下线
- 查看登录设备
- 查看最近访问时间

这会让 `tiny-security` 从底层库变成真正有产品感的安全框架。

---

## 19. 方法级鉴权设计

### 19.1 第一阶段

保留现有注解风格，底层继续可用 MVC + ThreadLocal。

### 19.2 第二阶段

逐步迁移为基于 Spring AOP / method interceptor 的方法鉴权。

优点：

- 非 Web 场景也能复用
- 服务层可直接加注解
- 更接近 Spring Security 的方法安全模型

### 19.3 推荐策略

- URL 鉴权负责粗粒度
- 方法注解负责细粒度

---

## 20. 与 Shiro / Spring Security 的参考对标

### 20.1 借鉴 Shiro 的点

- Subject / Session / Realm 的概念清晰
- 易理解的注解风格
- 在线会话管理能力强
- 踢人下线、rememberMe 等业务实用性高

建议借鉴：

- “在线会话管理”
- “并发登录控制策略”
- “清晰的主体模型”

### 20.2 借鉴 Spring Security 的点

- Filter Chain 思维
- Authentication / Authorization 职责分离
- EntryPoint / AccessDeniedHandler
- Method Security
- 扩展点标准化

建议借鉴：

- “认证链”
- “异常翻译”
- “Bean 可替换”
- “配置驱动 + 条件装配”

### 20.3 不建议照搬的点

- 不要一开始就引入过重 DSL
- 不要把概念设计得过多过深
- 不要为了“像 Spring Security”而增加接入复杂度

`tiny-security` 的价值恰恰在于轻量。

---

## 21. 向下兼容方案

### 21.1 兼容目标

让 `1.x` 用户可以低成本迁移到 `2.0`。

### 21.2 兼容策略

#### 1. 保留现有高频 API 外观

例如保留：

- `login(loginId)`
- `login(loginId, extraInfo)`
- `logout()`
- `getLoginId()`

底层转发到新架构。

#### 2. 旧配置项保留一段时间

例如：

- `store-type`
- `token-name`
- `timeout`
- `add-path`

在 `2.x` 中标记 deprecated，并在日志中提示新配置写法。

#### 3. 旧接口适配器

为当前 `AuthorizationInfoGet` 提供适配器：

```java
class AuthorizationInfoGetAdapter implements AuthorizationInfoProvider
```

这样现有用户无需马上改业务代码。

---

## 22. 测试设计

`2.0` 一定要把测试体系补上，不然框架演进会越来越难。

### 22.1 测试层次

- 单元测试
- 存储实现一致性测试
- starter 自动装配测试
- Web 集成测试
- 并发测试
- 兼容性测试

### 22.2 必测场景

- token 缺失 / 非法 / 过期
- session 过期
- logout 后不可再访问
- Redis / JDBC / memory 三种实现结果一致
- 并发登录策略正确
- 角色和权限注解组合正确
- URL 规则匹配正确
- ThreadLocal 清理正确

### 22.3 推荐测试工程

- `tiny-security-samples/sample-memory`
- `tiny-security-samples/sample-redis`
- `tiny-security-samples/sample-jdbc`

这样文档和测试也能复用。

---

## 23. 文档设计

文档是这个项目很关键的一部分，建议重构。

### 23.1 文档分层

- `README.md`
  - 只放介绍、亮点、快速开始
- `docs/quick-start.md`
- `docs/configuration.md`
- `docs/authentication.md`
- `docs/authorization.md`
- `docs/storage-memory.md`
- `docs/storage-redis.md`
- `docs/storage-jdbc.md`
- `docs/migration-1.x-to-2.x.md`
- `docs/faq.md`

### 23.2 README 应明确说明

- 支持的 Java / Spring Boot 版本
- 三种接入模式
- 核心能力边界
- 什么时候该选 tiny-security，什么时候该选 Spring Security

### 23.3 优先修复事项

- 全仓统一 UTF-8
- 修复 README 乱码
- 修正文档与实际版本不一致的问题

---

## 24. 版本演进路线

建议不要一口气做完，分三阶段推进。

### 24.1 v2.0.0-alpha

目标：完成架构骨架

- 拆分核心 SPI
- 引入 `SessionStore`
- 引入 `TokenSigner`
- 引入 `TokenResolver`
- 重构 starter 自动装配
- 修复默认 secret / cookie / logout 等安全问题
- 增加基础测试

### 24.2 v2.0.0-beta

目标：补齐生产核心能力

- 并发登录策略抽象
- 在线会话管理
- 权限缓存
- 异常翻译
- URL 规则模型
- 配置结构化

### 24.3 v2.0.0

目标：形成成熟可用版本

- 方法级鉴权增强
- 事件机制
- 兼容迁移文档
- sample 工程
- 完整 benchmark 与测试矩阵

### 24.4 v2.1+

可考虑后续能力：

- remember-me
- 多设备会话策略
- 多租户
- WebFlux 支持
- OAuth2 resource server 适配层

---

## 25. MVP 建议

如果要控制投入，我建议 `2.0` 第一批只做这些最有价值的事：

### 必做

- 修复安全默认值
- 统一 token / session 模型
- `AuthProvider` 保持 facade，真实能力下沉到 `SessionRepository`
- 重构 starter 可覆盖性
- 统一三种存储行为
- 补测试
- 修文档

### 强烈建议做

- 并发登录策略抽象
- 在线会话管理 API
- 异常处理扩展点
- 结构化配置

### 可以后置

- 表达式鉴权
- remember-me
- WebFlux
- 多租户深度支持

---

## 26. 推荐目录草案

```text
tiny-security
├─ docs
│  ├─ tiny-security-2.0-design.md
│  ├─ quick-start.md
│  ├─ configuration.md
│  └─ migration-1.x-to-2.x.md
├─ tiny-security-core
├─ tiny-security-web
├─ tiny-security-spring-boot-starter
├─ tiny-security-storage-memory
├─ tiny-security-storage-redis
├─ tiny-security-storage-jdbc
├─ tiny-security-test-support
└─ tiny-security-samples
```

---

## 27. 结论

`tiny-security` 现在已经具备成为“小而完整”的安全框架的基础，但要再往上走，关键不在于继续加几个注解，而在于完成以下升级：

- 从“一个大接口”升级为“清晰 SPI 体系”
- 从“可用默认值”升级为“安全默认值”
- 从“拦截器实现”升级为“认证与授权处理链”
- 从“功能点”升级为“框架能力”

如果这条路线走通，`tiny-security` 会形成一个很清晰的定位：

> 比 Spring Security 更轻，比单纯工具库更完整，比零散鉴权代码更规范。

这会是一个很有竞争力的位置。

---

## 28. 下一步建议

建议按这个顺序推进：

1. 先做 `2.0` 技术骨架拆分，不急着增加太多外部功能。
2. 先修安全基线和自动装配，再做会话管理与并发策略。
3. 先保证 memory / Redis / JDBC 三种实现行为一致，再扩展表达式和 remember-me。
4. 文档和 sample 与代码同步推进，不要最后补。

如果需要，我下一步可以继续直接帮你产出两份配套文档：

- `2.0` 的详细接口定义草案
- `1.x -> 2.0` 的迁移方案和任务拆解清单
