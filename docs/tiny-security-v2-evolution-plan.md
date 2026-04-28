# tiny-security v2 演进方案

## 1. 结论

可以，而且我建议就按这条路线推进。

这版方案的优点很明确：

- 不推翻当前已可用能力
- 不强行一次性重写
- 先抽象接口，再平移现有实现，风险低
- 每个阶段都能形成可发布版本
- 路线和 Shiro / Spring Security 的框架化方向一致，但仍保留 `tiny-security` 的轻量定位

相比直接做“大重构”，这版更适合作为 `v2` 的正式落地方案。

---

## 2. v2 总目标

`v2` 的核心目标是：

1. 保留当前 `AuthProvider + 注解 + starter` 的使用方式。
2. 把“拦截器里直接做所有事”的实现，演进成“可插拔安全链路”。
3. 把 single / redis / jdbc 三种实现统一到同一抽象下。
4. 把异常处理、权限校验、会话存储、事件通知拆成独立组件。
5. 为后续表达式授权、多认证方式、WebFlux 适配留下扩展位。

一句话概括：

> `v2` 不是推倒重写，而是把当前可用能力逐步内核化、组件化、链路化。

---

## 3. 总体架构

核心思路：

- `SecurityContext`：统一保存当前登录主体
- `AuthenticationManager`：只负责认证
- `AuthorizationManager`：只负责授权
- `SecurityInterceptorChain`：把 MVC 场景先组织成可插拔链路
- `ExceptionTranslator`：统一异常到 HTTP 响应
- `SessionRepository`：统一会话存储抽象
- `SecurityEventPublisher`：统一事件出口

推荐架构图：

```text
Request
  -> ExceptionTranslationInterceptor
  -> AuthenticationInterceptorAdapter
       -> AuthenticationManager
            -> BearerTokenResolver
            -> SessionRepository
            -> SecurityContextRepository
  -> AuthorizationInterceptorAdapter
       -> AuthorizationManager
  -> Controller
Response
```

请求完成后：

- `SecurityContextHolder.clear()`

这条链路能保持当前 MVC 方案不变，同时把核心职责从现有拦截器中拆出来。

---

## 4. 推荐包结构

这个结构是合理的，可以直接作为 `v2` 的目标目录布局：

```text
org.tinycloud.security
  ├─ autoconfigure
  │   ├─ TinySecurityAutoConfiguration
  │   └─ TinySecurityProperties
  ├─ context
  │   ├─ SecurityContext
  │   ├─ SecurityContextHolder
  │   └─ SecurityContextRepository
  ├─ authentication
  │   ├─ AuthenticationToken
  │   ├─ AuthenticationResult
  │   ├─ AuthenticationProvider
  │   ├─ AuthenticationManager
  │   └─ BearerTokenResolver
  ├─ authorization
  │   ├─ AuthorizationDecision
  │   ├─ AuthorizationManager
  │   ├─ AnnotationAuthorizationManager
  │   ├─ UrlAuthorizationManager
  │   └─ PermissionEvaluator
  ├─ session
  │   ├─ SessionRepository
  │   ├─ SingleSessionRepository
  │   ├─ RedisSessionRepository
  │   └─ JdbcSessionRepository
  ├─ web
  │   ├─ SecurityInterceptorChain
  │   ├─ AuthenticationInterceptorAdapter
  │   ├─ AuthorizationInterceptorAdapter
  │   └─ ExceptionTranslationInterceptor
  ├─ event
  │   ├─ SecurityEvent
  │   ├─ LoginSuccessEvent
  │   ├─ LoginFailureEvent
  │   └─ AuthorizationFailureEvent
  └─ support
      ├─ DefaultExceptionTranslator
      └─ DefaultPermissionCache
```

我建议仅补一个小调整：

- `exception`
  - 放认证、授权、并发超限等异常类型

因为异常体系后面会比较独立，单独分包会更清晰。

---

## 5. 核心组件职责

### 5.1 SecurityContext

职责：

- 保存当前请求对应的登录主体
- 作为全链路统一上下文
- 替代零散的 `AuthenticationHolder` / `AuthorizationHolder`

建议最小结构：

```java
public class SecurityContext {
    private LoginSubject subject;
    private Set<String> roles;
    private Set<String> permissions;
}
```

### 5.2 SecurityContextHolder

职责：

- 对外提供统一上下文访问入口
- 第一阶段内部仍可以基于 `ThreadLocal`
- 后续可扩展为不同上下文策略

建议暴露：

- `getContext()`
- `setContext(SecurityContext context)`
- `clearContext()`

### 5.3 SecurityContextRepository

职责：

- 负责上下文加载 / 保存 / 清理
- 当前阶段可以先只做“请求内管理”
- 后续如果支持 remember-me、复合认证方式，会很有用

---

## 6. 认证设计

### 6.1 AuthenticationManager

职责边界应该明确为：

- 从请求中提取 token
- 校验 token 是否有效
- 解析 credentials
- 从 `SessionRepository` 取会话
- 检查是否过期
- 需要时刷新会话
- 构建 `AuthenticationResult`

最小接口：

```java
public interface AuthenticationManager {
    AuthenticationResult authenticate(HttpServletRequest request);
}
```

### 6.2 AuthenticationResult

建议不要只返回 `LoginSubject`，而是带一点状态信息：

```java
public class AuthenticationResult {
    private boolean authenticated;
    private LoginSubject subject;
    private String credentials;
}
```

后续如果做：

- 强制刷新
- 附带失败原因
- token 类型区分

都更方便。

### 6.3 BearerTokenResolver

这个方向我也建议保留。

但为了兼容老项目，建议第一阶段支持三种来源：

- Header
- Cookie
- RequestParam

同时通过 `strict-bearer` 决定是否强制要求：

- `Authorization: Bearer xxx`

建议接口可以先叫：

```java
public interface BearerTokenResolver {
    String resolve(HttpServletRequest request);
}
```

如果后续支持 API Key，可以再把命名放宽成 `TokenResolver`。

---

## 7. 授权设计

### 7.1 AuthorizationManager

职责只做授权判断，不做认证兜底。

最小接口：

```java
public interface AuthorizationManager {
    AuthorizationDecision check(HttpServletRequest request, Method handlerMethod, LoginSubject subject);
}
```

这很适合第一阶段落地。

### 7.2 AuthorizationDecision

建议最小结构：

```java
public class AuthorizationDecision {
    private boolean granted;
    private String reason;
}
```

后续如果需要日志、事件、指标，这个 `reason` 很有用。

### 7.3 AnnotationAuthorizationManager

职责：

- 处理 `@RequiresPermissions`
- 处理 `@RequiresRoles`
- 兼容 `@Ignore`

建议第一阶段先完全兼容老注解行为，不改业务使用方式。

### 7.4 UrlAuthorizationManager

职责：

- 处理 `perm-check-mode=URL`
- 作为 URL 维度授权实现

这样注解模式和 URL 模式都收敛到统一接口下。

### 7.5 PermissionEvaluator

职责：

- 统一封装 `hasRole` / `hasPermission` / `hasAny` / `hasAll`
- 避免逻辑散落在 `AuthUtil`

这个组件抽出来以后，表达式授权也能直接复用。

---

## 8. SessionRepository 抽象

你给的这个最小接口是对的，足够作为 `M2` 基础版本：

```java
public interface SessionRepository {
    LoginSubject findByCredentials(String credentials);
    void save(LoginSubject subject, int timeoutSeconds);
    boolean refresh(String credentials, LoginSubject subject, int timeoutSeconds);
    boolean deleteByCredentials(String credentials);
    int countOnline(Object loginId);
}
```

我建议再补两个方法，长期更稳：

```java
boolean deleteByLoginId(Object loginId);
boolean exists(String credentials);
```

原因：

- `exists` 可以避免某些场景下把 `findByCredentials` 当探测接口
- `deleteByLoginId` 你当前已有能力，保留抽象更完整

### 8.1 三种实现迁移方式

迁移原则：

- 先不大改逻辑
- 直接把现有 Single / Redis / JDBC 的存储逻辑平移到 `SessionRepository`
- `AuthProvider` 只保留 facade 行为

对应关系：

- `store-type=single` -> `SingleSessionRepository`
- `store-type=redis` -> `RedisSessionRepository`
- `store-type=jdbc` -> `JdbcSessionRepository`

### 8.2 AuthProvider 在 v2 的角色

建议改成：

- 向后兼容 facade
- 对外保留原有 API
- 内部委托给：
  - `AuthenticationManager`
  - `SessionRepository`
  - `SecurityContextHolder`

也就是说：

> `AuthProvider` 在 v2 不再是核心实现，而是兼容外观层。

这个定位很重要。

---

## 9. Web 适配层设计

### 9.1 SecurityInterceptorChain

职责：

- 组织认证、授权、异常翻译三个环节
- 对 MVC 暴露为统一适配器

建议第一阶段不用做太复杂，核心是“链式职责清晰”。

### 9.2 AuthenticationInterceptorAdapter

职责：

- 调用 `AuthenticationManager`
- 认证成功后写入 `SecurityContextHolder`
- 认证失败抛出统一异常

### 9.3 AuthorizationInterceptorAdapter

职责：

- 调用 `AuthorizationManager`
- 认证通过但授权失败时抛出 `NoPermissionException`
- 未登录场景应返回 `UnAuthorizedException`

这点我完全同意你提的调整：

> `AuthorizationInterceptor` 在未登录场景返回 `UnAuthorizedException`

这样 `401 / 403` 语义会更清晰。

### 9.4 ExceptionTranslationInterceptor

职责：

- 捕获链路异常
- 委托 `ExceptionTranslator`
- 统一输出 401 / 403 / 409 JSON

第一阶段非常值得优先做。

---

## 10. ExceptionTranslator 设计

这个是第一批最值得落地的组件之一。

最小接口：

```java
public interface ExceptionTranslator {
    void translate(HttpServletRequest req, HttpServletResponse resp, Exception ex);
}
```

默认映射建议：

- `UnAuthorizedException` -> `401`
- `NoPermissionException` -> `403`
- `ConcurrentLoginOverLimitException` -> `409`
- 其他安全异常 -> `400` 或 `500`

建议默认返回统一 JSON：

```json
{
  "code": 401,
  "message": "Unauthorized",
  "path": "/api/user/list",
  "timestamp": 1710000000000
}
```

### 10.1 为什么优先级高

因为它能立刻解决三个痛点：

- 认证和授权异常输出不统一
- 使用者需要自己兜底处理异常
- 很难稳定做自动化测试

---

## 11. 事件机制设计

### 11.1 SecurityEventPublisher

建议第一阶段只做一个很轻的发布接口：

```java
public interface SecurityEventPublisher {
    void publish(SecurityEvent event);
}
```

默认实现：

- 基于 Spring `ApplicationEventPublisher`
- 如果没有 Spring 上下文，也可 no-op

### 11.2 第一批事件

完全可以先按你列的最小集合来：

- `LoginSuccessEvent`
- `LoginFailureEvent`
- `AuthorizationFailureEvent`

建议再补一个：

- `ConcurrentLimitExceededEvent`

因为并发超限通常是独立监控点。

---

## 12. 向后兼容策略

这一部分我完全赞同，而且建议作为 `v2` 核心原则写死。

### 12.1 API 兼容

保留：

- `AuthProvider` 全部现有方法签名
- `@Ignore`
- `@RequiresPermissions`
- `@RequiresRoles`
- `AuthUtil`

做法：

- 内部改为委托到新组件
- 外部调用方式不变

### 12.2 配置兼容

保留现有 `tiny-security.*` 配置。

新增扩展配置：

- `tiny-security.strict-bearer`
- `tiny-security.cookie.secure`
- `tiny-security.cookie.same-site`
- `tiny-security.jwt.fail-fast-if-default-secret`

我建议再补两个：

- `tiny-security.exception-translation-enabled`
- `tiny-security.permission-cache-enabled`

这样第一阶段开关更完整。

### 12.3 行为兼容

原则：

- 默认行为尽量不破坏旧项目
- 更安全的新行为通过开关启用
- 先告警，再强制

这个节奏非常适合开源框架演进。

---

## 13. 四个里程碑评估

你给的 4 个里程碑是合理的，我建议直接采用。

### M1：一致性与安全基线

目标：

- 修复 `401 / 403 / 409` 语义
- `@Ignore` 语义统一
- README 与实现对齐
- 默认异常翻译器可用

这是最容易发布、收益也最高的一阶段。

### M2：组件抽象落地

目标：

- 引入 `SessionRepository`
- 引入 `AuthenticationManager`
- 引入 `AuthorizationManager`
- `AuthProvider` 改为 facade 类（不再承担底层存储实现）

这是 `v2` 真正的架构分水岭。

### M3：可运维能力

目标：

- 事件
- 权限缓存
- metrics

这阶段会显著提升框架“生产可用性”。

### M4：能力扩展

目标：

- 表达式授权
- 多认证方式
- WebFlux 支持

这部分适合在前 3 个里程碑稳定后再做，不建议前置。

---

## 14. 第一批改造任务单

我建议把第一批任务正式定为下面这些，和你给的列表保持一致，只补一点顺序。

### 第一优先级

1. 新增 `ExceptionTranslator` 和默认 MVC 异常处理器
2. 调整 `AuthorizationInterceptor` 在未登录场景抛 `UnAuthorizedException`
3. 调整 `@Ignore` 在认证 / 授权链中的统一语义
4. 修正文档中的 Bearer 示例、token 说明、timeout/JWT 说明

### 第二优先级

5. 新增 `SessionRepository` 接口
6. 给 single / redis / jdbc 落地真实 repository 实现
7. 保留 `AuthProvider` facade，不改外部使用方式

### 第三优先级

8. 增加基础测试：
   - 认证成功
   - token 缺失
   - 无权限
   - 并发超限

---

## 15. 我建议的具体实施顺序

如果我们接下来开始动代码，我建议顺序是：

1. 先做 `M1`
2. 再抽 `SessionRepository`
3. 再抽 `AuthenticationManager`
4. 再抽 `AuthorizationManager`
5. 最后把原拦截器改成 adapter

原因很简单：

- `M1` 风险最低，能先把项目边界稳定下来
- 先抽存储，再抽认证，会比直接抽全链路更稳
- 原拦截器先保留壳子，迁移成本最低

---

## 16. 推荐落地结论

最终建议如下：

- 采用你这版 `v2` 演进设计作为正式路线
- 第一阶段不追求模块大拆分，先在现有模块内完成抽象升级
- `AuthProvider` 明确保留为兼容 facade
- `SessionRepository + AuthenticationManager + AuthorizationManager + ExceptionTranslator` 作为第一批核心抽象
- 先做 `M1 + M2`，完成后就能形成一个很扎实的 `v2 alpha`

这条路线是“能落地、风险可控、能持续发版”的方案，我建议就按这个方向推进。

---

## 17. 下一步

接下来可以直接进入实现阶段，建议优先做：

1. `M1` 改造
2. 补测试
3. 再进入 `M2`

如果你愿意，我下一步可以直接开始按这份方案动代码，先把 `M1` 的第一批改造任务做掉。
