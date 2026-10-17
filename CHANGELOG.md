# tiny-security 升级日志（CHANGELOG）

> 分支：`springboot3`（Spring Boot 3.x / JDK 17+）
> 数据来源：基于 `springboot3` 分支 first-parent 主线，按版本发布提交逐段切分
> 版本区间：`1.2.0`（2025-05-14）→ `1.5.0`（待发版）
> 更早基线：`1.1.0 全新版本发布`（2024-09-06，springboot3 重生起点）

---

## 1.5.0

> 升级路径：1.4.0 → 1.5.0 ｜ 本次为**移除 JWT + 凭证固定为 UUID**（破坏性变更）

### ⚠️ 行为变更（升级必读）

- **移除 JWT，token 改为 HMAC-SHA256 签名信封**：token 形态从 `Bearer <JWT>` 变为
  `Bearer <credentials>.<base64url(HMAC-SHA256(credentials, token-secret))>`。
  - **不再依赖 `com.auth0:java-jwt`**（签名改用 JDK 自带的 `javax.crypto`），依赖树更干净；token 里**没有算法字段**，算法在代码中写死 `HmacSHA256`，`alg=none` / 算法混淆风险面归零。
  - **移除第二条过期时间线**：原先 JWT 有效期取 `max(jwt-timeout, 会话 timeout)`，有效期有两个来源；现在 token 只是凭证的签名信封，**有效期完全以会话为准**（`tiny-security.timeout`）。
  - token 格式与签名算法都变了，**升级后所有老 token 立即失效**，在线用户需重新登录。
- **配置项重命名与删除**：
  - `tiny-security.jwt-secret` → **`tiny-security.token-secret`**（未配置时仍自动生成临时随机密钥并打印 WARN，行为不变）
  - **删除** `tiny-security.jwt-subject`、`tiny-security.jwt-timeout`（不再有任何作用，即使配置了也不会生效）
- **常量重命名**：`AuthConsts.JWT_TOKEN_PREFIX` → `AuthConsts.TOKEN_PREFIX`（值仍为 `"Bearer "`，解析行为不变）。**破坏性**：若外部代码引用了旧常量名，请改用 `TOKEN_PREFIX`。
- **`AuthProvider.getCredentialsByToken(String)` 对外行为不变**（仍返回 `credentials`、失败抛 `UnAuthorizedException`），仅内部由"解码 JWT"改为"验签后取 credentials"，调用方无需改动。**破坏性**：`JwtUtil` 工具类**已删除**，直接使用过它的代码需改用 `TokenSignUtil`。
- **删除 `credentials-style` 配置项，凭证固定为 UUID**：凭证是会话的唯一钥匙，而可选的凭证风格只会带来"用户选到弱随机源"的风险，收益为零。
  - 现在固定为 `UUID.randomUUID().toString().replace("-", "")`（32 位十六进制，内部走 `SecureRandom`，122 bit 随机性）——**与原默认值 `uuid` 逐字节一致**，因此从未显式配置过 `credentials-style` 的项目**凭证格式不变**。
  - **删除** `tiny-security.credentials-style`（即使配置了也不再生效）。若曾配成 `random128` / `nanoid`，升级后凭证格式统一变为 32 位十六进制。
  - **破坏性**：工具类 `CredentialsGenUtil` 与 `org.tinycloud.security.util.idgen.NanoId` 一并**删除**。直接调用过它们的代码需自行替换，UUID 一行即可：`UUID.randomUUID().toString().replace("-", "")`。
- **凭证碰撞不再静默覆盖**：四个会话仓储的 `save` 由"无条件写入"改为"不存在才写入"（`single` 用 `putIfAbsent`、`caffeine` 用 `asMap().putIfAbsent`、`redis` 用 `setIfAbsent`、`jdbc` 由 `credentials` 唯一约束拦下）。
  - 碰撞时 `save` 返回 `false`、登录失败并打印 ERROR 日志，**不再覆盖已有会话**。
  - 碰撞概率约 2⁻¹²²，正常永远不会触发；一旦触发，说明随机源异常或有人在构造会话固定攻击。
  - **破坏性**：自定义实现 `SessionRepository` 时，`save` 也应在凭证已存在时返回 `false`，与该语义保持一致。
- **`WebRequestUtils` 的便捷重载不再从 URL 参数读取 token**：`getToken(request, tokenName)` 等便捷重载的 `enableUrlToken` 默认值由 `true` 改为 **`false`**，与框架自身策略（`tiny-security.enable-url-token` 默认 `false`）对齐 —— URL 上的 token 会进入访问日志与 Referer 头，造成凭证泄露。
  - **破坏性**：此前依赖便捷重载从 `?token=xxx` 取 token 的代码将取不到值。确需从 URL 读取时，请显式调用四参重载 `getToken(request, tokenName, enableCookie, true)`。
  - **不受影响**：`AuthProvider` 内部一直显式调用四参重载，**生产鉴权路径行为完全不变**。
- **`SM3Hash` / `SimpleHash` 的 `salt=null` 语义修正，会改变哈希值**：此前 `(source + salt)` 把 `null` 拼成了字面量 `"null"`（导致 `salt=null` 与 `salt="null"` 产生同一哈希），现在 `null` 统一归一化为空串，等价于"不加盐"。
  - **破坏性**：以下调用的哈希结果会变，**用它存储过的哈希将无法再校验通过**，需重新生成或做数据迁移：
    - `new SimpleHash("SM3", source)` —— 两参构造内部传的正是 `null`
    - `new SimpleHash("SM3", source, null)` / `new SimpleHash("SM3", source, null, n)`
    - `new SM3Hash(source, null)` / `new SM3Hash(source, null, n)` / `setSalt(null)`
  - **不受影响**：`salt` 非 null（含 `""`）的调用；`new SM3Hash(source)`（单参构造，盐本就是 `""`）；`SimpleHash` 的所有 JDK 算法分支（其 `null` salt 语义本来就是"不加盐"）。

- **`AuthUtil` 不再依赖静态门面，`TinySecurityFacade` 降为内部实现**：
  - `AuthUtil` 现在每次调用都从**当前请求的 `WebApplicationContext`** 解析 `AuthProvider`（框架唯一的实例门面），不再持有任何可变静态全局状态。因此用户自定义 `AuthProvider` / `SecurityContextRepository` / `AuthorizationInfoGet` 都不会再影响 `AuthUtil` —— 容器里放的是谁，它就用谁。
  - **破坏性**：`AuthUtil.setFacade(...)` 与 `AuthUtil.getFacade()` **已删除**；`TinySecurityFacade` **不再是公开类**（移入 `org.tinycloud.security.provider` 包且为包级私有），容器里也不再注册 `tinySecurityFacade` Bean。
  - **`AuthUtil` 的公开方法签名与语义完全不变**，`AuthUtil.getLoginId()` / `hasRole()` 等调用方**无需任何改动**。
  - **限制**：`AuthUtil` 只适用于持有当前请求的线程。`@Async` / MQ 消费线程等非 Web 线程取不到请求、抛 `UnAuthorizedException`（与 `1.5.0` 之前一致）；这类场景请直接注入 `AuthProvider`。**这是有意取舍、非待修缺陷** —— 线程绑定的上下文（同 `RequestContextHolder`、Spring Security 的 `SecurityContextHolder`）切线程后本就失效，框架不做自动传播。
  - 若曾手工 `new TinySecurityFacade(repo)` 或自定义过它的 Bean：该类已不是公开 API，请改用 `AuthProvider`；手工 `new AuthProvider(sessionRepository, properties, publisher)` 的既有写法**仍然可用**（内部退化为默认 `ThreadLocalSecurityContextRepository` + 无 SPI，与旧行为一致）。
- **`tiny-security.timeout` 现在只接受「正数」，未配置沿用 1800；任何非正值都会在启动时报错**：
  - `null`（未配置）→ 1800 秒；正数 → 正常超时秒数；**`0` 与一切负数（含 `-1`）→ 启动直接失败并给出明确报错**。
  - **为什么加校验**：此前 `timeout` 没有任何校验，同一个非正值在四个仓储下会变成**四种互不相同的静默行为** —— `single` 永不过期、`caffeine` 立即驱逐、`redis` 登录失败、`jdbc` 立即过期。配置写错不会有任何提示，只会表现为诡异症状。
  - **破坏性**：若 `tiny-security.timeout` 配过 `0`、`-1`、`-2` 等非正值，**升级后启动会直接失败**。请改为一个正数秒数。
  - **注意 `-1` 不再表示"永不过期"**：`1.5.0` 开发期间曾短暂支持 `timeout = -1`，**该语义已取消**。原因是"会话永不过期"对安全框架是反模式（凭证一旦泄露就永无失效），且会让"存储层 TTL"与 `loginExpireTime` 两套过期口径分叉（`AuthProvider.refreshByCredentials(credentials, subject)` 只维护前者）。若确实需要长时间会话，请配置一个足够大的正数（例如 `86400`）。
  - **不受影响**：正数与未配置。

### 🔒 安全加固

- **内核补上会话的「绝对过期」校验**：此前 `DefaultAuthenticationManager` 只判断"剩余有效期是否不足 TTL 的 20%"，**从不判断会话是否已过期**。而续期条件（`剩余 ≤ 阈值`）对已过期会话**恒成立**（剩余为负数），于是一个早已失效的会话只要被读到，就会被改写成 `now + timeout` 从而**无限复活**。
  - 之所以不能依赖仓储来判定：`SessionRepository.getSubject` 的契约里**没有**"过期返回 null"这条承诺（只写了 `@return 登录主体`），而 README 又明确鼓励用户自定义 `SessionRepository` —— 对自定义实现而言这是**实打实的会话失效绕过**。
  - 而且**即便用内置仓储也并非够不着**：`save(subject, timeoutSeconds, max)` 的「存储层 TTL」与 `subject.loginExpireTime` 是两个独立参数，仓储并不校验二者一致。已实测出"存储层仍有效、`loginExpireTime` 已过期 60 秒"的会话会被 `getSubject` 正常返回（`checkByCredentials` 也返回 `true`），旧逻辑会把它**放行并续期复活**。
  - 现在内核在续期判断**之前**先做一次 `expireTime <= now → 401`：会话是否过期由内核判定，不再外包给插件。
  - **顺带加固**：仓储返回的 `LoginSubject` 若缺 `loginExpireTime`，原先会拆箱抛 `NullPointerException`（HTTP 500），现在按"会话已失效"返回 401。
  - **行为变更（少见但存在）**：若曾用 `AuthProvider.refreshByCredentials(credentials, subject)` 手工延长会话、且传入的 `subject.loginExpireTime` 已经过期（即两个过期口径不一致），该会话此前能继续使用（旧逻辑会顺手把它续期），**升级后会返回 401**。这是有意为之 —— 不一致的会话状态应当被拒，而不是被悄悄续命。
  - **不受影响**：由框架正常签发与续期的会话。
- **修复登录主体缺 `loginExpireTime` 时的两处不一致行为**：
  - `LoginSubject.loginExpireTime` 是**装箱 `Long`**，缺字段时内核原先会直接拆箱抛 `NullPointerException`（HTTP 500），现在按"会话已失效"返回 401。
  - `caffeine` 仓储的 `nanosUntilExpire` 同样会拆箱抛 NPE（表现为 `save` 返回 false）；现在与内核口径统一，按"已过期"处理。`jdbc` / `redis` / `single` 本来就已是 fail-closed，无需改动。

- **`CommonUtil.getRandomString` 改用 `SecureRandom`**：此前使用 `ThreadLocalRandom`（非密码学安全随机源，内部状态只有 64 位且可被观测输出反推）。该函数现在只服务于「未配置 `token-secret` 时生成临时签名密钥」，改用 `SecureRandom` 后兜底密钥的材料质量合格。
- **清除可预测随机源的所有可达路径**：随 `CredentialsGenUtil` / `NanoId` 一并移除，框架内**不再存在任何非 CSPRNG 的凭证或密钥来源**——凭证只有 UUID，签名密钥只有"配置值"或 `SecureRandom`。
- **URL 鉴权模式补上 HTTP Method 维度**（`tiny-security.perm-check-mode: URL`）：
  - **修复的问题**：此前 URL 模式只用 `request.getRequestURI()` 做 Ant 匹配、**完全不看 Method**，于是「拥有 `GET /user` 读权限」等价于「拥有 `DELETE /user` 权限」—— **只读账号可以调用删除接口**。
  - **修复方式**：权限码支持 `METHOD 路径` 写法（中间一个空格，Method 大小写不敏感）—— `GET /user/**` 只匹配 GET、`POST /user/**` 只匹配 POST、`* /user/**` 匹配任意 Method。读写分离的接口写成两条权限码即可隔开。
  - **向后兼容（非破坏性变更）**：**不写 Method 的权限码行为完全不变**，仍匹配任意 Method。存量用户配置的都是裸路径（README 原要求权限码与接口 URL 相匹配），升级后无需任何改动，只是无法享受新能力。
  - 业务权限码（如 `system:user:add`，含冒号）会被识别为裸路径，不会被误截断成 Method。
  - ⚠️ **context-path 提醒**：权限码匹配的是**含 context-path 的完整 URI**。修改应用的 context-path 会导致既有权限码全部失配（表现为相关用户全部 403；fail-closed 不越权，但需同步调整配置）。详见 README §2.3.3。
  - **匹配器保持 `AntPathMatcher`（经实测决定不替换为 `PathPattern`）**：`PathPattern` 修不了编码绕过（那是输入源问题，与匹配器无关）、现有权限码词汇表在两者下结论完全一致，而路径**中间**的 `**`（如 `/user/**/edit`）在 `PathPattern` 下会直接抛 `PatternParseException`，属破坏性变更。故本项维持现状，不构成任何升级动作。

### 🐛 缺陷修复

- **修复并发登录上限（`maxConcurrentLogins`）非原子导致的两种错误行为**（真实环境实测复现）：
  - **症状一：配了上限的账号在突发登录下谁都登不进来。** `redis` 仓储原先是"先 count 判断 + push 后再查一次 size，超了就摘掉自己"的两道非原子闸门。上限为 `1` 时若多个请求同时看到"当前 0 人"，它们会各自 push、再各自发现超额、各自摘掉自己 —— 实测 4 个并发登录 **0 成功、4 个全被拒**，而在线列表里一个人都没有（空位明明还在）。
  - **症状二：上限被静默突破。** `single` / `caffeine` / `jdbc` 只有第一道闸门，并发请求都通过检查后全部写入。实测 `jdbc`（H2）在上限为 `3` 时 16 个并发登录 **16/16 全部成功**。
  - **修复**：`redis` 新增 Lua 脚本，把"判断上限 + 入列 + 设置列表 TTL"合并为**一次原子执行**（脚本只操作一个键，保证 Redis Cluster 下不跨 slot）；`single` / `caffeine` 把上限判断挪进它们**已有的** `onlineLock` 内，与入列同锁。三处都改为**先写会话、再原子占名额**，并在占名额失败（含该步骤自身抛异常）时**回滚刚写入的会话** —— 否则会留下一个不在在线列表里、却可以正常使用的会话，等于绕过上限。
  - **验证**：新增本仓库首批并发用例（16 线程同栅栏、`max=3`，断言恰好 3 个成功），去掉原子守卫后如实变红（`single` 4 个成功、`caffeine` 13 个成功）；`redis` 侧由真实 Redis 探针验证修复前后分别为 0/4 与 1/4 成功。
  - **已知残余（`jdbc`）**：JDBC 的"先 COUNT 再 INSERT"要真正原子必须让两步同处一个临界区，而该仓储只有裸 `JdbcTemplate`（每条语句自动提交）、没有事务管理器。三个**不改表结构**的候选方案已逐个实测否决：① 单条条件 `INSERT ... SELECT ... WHERE (SELECT COUNT ...) < ?` 实测 16/14 行 ≠ 3（子查询不加锁）；② 事务 + `SELECT COUNT ... FOR UPDATE` 在 H2 上直接报 `FOR UPDATE is not allowed in DISTINCT or grouped select`；③ 事务 + 行锁 `SELECT ... FOR UPDATE` 只能锁住已存在的会话行，账号会话数为 0 时无行可锁，而 H2 / PostgreSQL 无间隙锁。**因此 JDBC 当前仍是 best-effort：串行登录守上限，并发下会突破。**彻底闭合需要改表结构（如按 `(login_id, slot)` 建唯一索引，或加一张"每账号一行"的锁表配合事务），对既有部署是破坏性 DDL，故未在本次实施。
- **修复 `AuthUtil.hasRole` / `hasPermission` 在无权限注解接口上恒返回 `false` 的回归**（1.3.1 引入）：
  - **根因**：1.3.1 为"只做注解需要的 SPI 调用"做性能优化后，授权管理器仅当方法上存在 `@RequiresRoles` / `@RequiresPermissions` 时才去查对应的角色/权限集合，无注解接口更是直接放行、一次都不查。于是 `SecurityContext` 里的 `roleSet` / `permissionSet` 恒为空集，而 `AuthUtil.hasRole/hasPermission` 读的正是这个空集 —— 代码式鉴权 API 静默失效（只声明 `@RequiresPermissions` 时 `hasRole` 为 false，只声明 `@RequiresRoles` 时 `hasPermission` 为 false）。
  - **修复**：保留原有性能设计（无注解接口**依然不做任何 SPI 调用**），把加载时机推迟到 `AuthUtil.has*` 真正被调用时，由 `TinySecurityFacade` 按需懒加载，并把结果缓存回本次请求的上下文（每类数据每次请求最多查一次）。
  - `SecurityContext` 现在区分「尚未加载」与「已加载但确实为空」（新增 `isRoleSetLoaded()` / `isPermissionSetLoaded()`），只有前者才触发懒加载；`getRoleSet()` / `getPermissionSet()` 的返回值语义不变（未加载时仍是空集合）。
  - **新增** `TinySecurityFacade(SecurityContextRepository, AuthorizationInfoGet)` 构造重载；原单参构造保留且行为不变（不做懒加载）。**经 starter 自动配置的用户无需任何改动** —— `AuthAutoConfiguration` 已自动注入 `AuthorizationInfoGet`。
- **修复 `checkLogin()` 对畸形 token 抛 `IllegalArgumentException` 导致 HTTP 500 而非 401**：
  - **触发**：token 的凭证部分是 `credentials.signature` 的分隔符左侧内容。`TokenSignUtil.sign` 用 `Assert.hasText` 拦住空凭证，但**用同一 secret 自行计算 HMAC 即可绕过**（同密钥的其他用途、或密钥泄露场景）—— `" " + "." + base64url(HMAC-SHA256(" ", secret))` 这种 token 能通过验签并原样返回凭证 `" "`。
  - **症状**：`checkLogin()` 把 `" "` 交给会话仓储，命中内置仓储的 `Assert.hasText(credentials, ...)` 抛出 `IllegalArgumentException`。它**不是** `TinySecurityException`，异常解析器返回 null，最终交给 Spring 默认处理 → **HTTP 500**（调用方会误判为服务端故障，也会污染错误监控）。
  - **修复**：`checkLogin()` 补 try/catch —— `UnAuthorizedException` 原样抛出，其余异常按"未登录"处理并降为 debug 日志，最终统一抛 `UnAuthorizedException`（401）。与 `isLogin()` 的既有容错写法对齐：两者只该在"抛异常还是返回 false"上不同，对异常输入的容错必须一致。
  - **不受影响**：正常 token；以及未登录（无 token）的常见路径（本来就抛 `UnAuthorizedException`）。
- **修复登录失败时，事件监听器抛出的异常会顶掉真实失败原因**：
  - **症状**：`login()` 在 catch 块里直接调用 `publishLoginFailure(...)`，**没有单独保护**。若监听器（审计落库、风控告警等）自身抛异常，该异常会替换掉登录失败的原始异常 —— 调用方与异常翻译器看到的是监听器的报错，**看不到真实失败原因**，排障时会被彻底带偏（例如真实原因是"已超过并发登录上限"，前端却收到监听器抛出的 NPE）。
  - **修复**：失败路径的事件发布补上独立的 `try/catch` + WARN 日志，与**成功路径既有的隔离写法对齐**（成功路径本就已隔离，无需改动）。发布失败只记录日志，原始异常照常抛出。
  - **不受影响**：正常登录失败（监听器不抛异常时行为完全不变）。
  - **本次未做的部分**：`LoginSuccessEvent` 仍携带完整 token、发布策略仍为同步 —— 这两条属**公开 API 变更 / 新特性**（`getToken()` 是已发布 API，改成不可逆标识会让存量监听器拿不到 token），留待后续版本与事件机制一并重做。
- **修复 `getToken()` 与 `login()` 的 token 前缀语义不一致**：
  - **症状**：`login()` 返回**带 `Bearer ` 前缀**的值，而 `getToken()` 返回**去掉前缀**的裸值。用户按直觉把 `getToken()` 的返回值放回请求头，会直接 401 —— 两个 API 形态不一致，且 `AuthConsts.TOKEN_PREFIX` 的 javadoc 本就写明「token 在请求中与**登录返回值里**都以此前缀开头」，是 `getToken()` 违反了该约定。
  - **修复**：`getToken()` 统一返回**带前缀**的完整值（与 `login()` 同形、可直接放回请求头）；新增 `getRawToken()` / `getRawToken(request)` 提供去前缀的裸值（内部鉴权链路继续用裸值，`getCredentialsByToken` 本就容忍两种形态，故生产鉴权路径行为不变）。
  - **行为变更**：依赖 `getToken()` 旧行为的代码请改用 `getRawToken()`（已列入升级检查清单）。
- **消除两处「静默配置错误」**（`1.5.0`）：
  - **`cookie-same-site: NONE` + `cookie-secure: false`**：这是**非法组合** —— `SameSite=None` 的 Cookie 规范要求必须伴随 `Secure`，否则浏览器会**直接丢弃**该 Cookie，表现为「登录成功但下一个请求又未登录」（与 P1-5 是同一类症状）。现在装配期检测并打印 WARN（含两种修法）。**只告警、不擅自改写用户配置**：强开 Secure 会让纯 http 调试环境反而丢 Cookie，框架替用户猜这个会引入歧义。仅在 `enable-cookie=true` 时提示。
  - **`token-secret` 过短**：HMAC-SHA256 的密钥短于摘要长度（32 字节）会削弱抗暴破强度，而此前只判非空（`token-secret: 123` 也接受）。现在短于 32 字节会打印 WARN（含实际字节数与 `openssl rand -base64 48` 建议）。**未采用强制最小长度** —— 那会让存量配置升级后直接启动失败，属破坏性变更。
- **修复 `AuthProvider.refreshByCredentials(credentials, subject)` 续期"不生效"**：
  - **症状**：该方法只延长**存储层 TTL**，**从不更新 `subject.loginExpireTime`**。而内核的「绝对过期校验」判定的正是这个时间戳 —— 两套过期口径分叉后，存储里的会话明明还有 TTL，用户却已经 401，**表现为续期没生效**。旧逻辑靠"下一跳顺手续期"把这条缝盖住了，所以一直没暴露。
  - **实测比预期更严重**：在 `store-type: single`（默认值）下，`SingleSessionRepository` 的有效性判定同样读 `loginExpireTime`，时间戳停在过去时 `getSubject` **直接返回 `null`** —— 会话根本读不回来（`checkByCredentials` 也返回 false），而不仅仅是"读到了但被判过期"。
  - **修复**：刷新时同步把 `loginExpireTime` 推进到 `now + timeout`，让「存储层 TTL」与「绝对过期时间戳」两套口径合一。这与内核自身的滑动续期路径（`DefaultAuthenticationManager` 先 set 再 refresh）本就是同一口径，本次只是让公开 API 与内核对齐。
  - **行为变更**：本方法会**改写传入的 subject**（写入新的过期时间戳）。若调用方此前自行设置了**更长**的过期时间，现在会被收敛为 `timeout` —— 这是"口径合一"的目的所在，属修正而非能力削减。`subject` 传 `null` 时不抛异常，退化为纯 TTL 延长。
  - **不受影响**：正常请求链路（内核自己的续期逻辑本就正确，未作改动）。
- **修复 Cookie 模式下"登出后仍是登录态"与"显式传 request 时 Cookie 不清理"两个缺陷**（需开启 `tiny-security.enable-cookie`）：
  - **缺陷一（登出静默失效）**：删除 Cookie 时只带了 `path`/`maxAge=0`/`HttpOnly`，**丢了 `Secure` 与 `SameSite`**。删除 Cookie 的本质是"写回一个同名、`maxAge=0` 的 Cookie"，浏览器只有在 `path`/`domain` 与**安全属性**都匹配时才认这条删除指令；`SameSite=None` 的 Cookie 规范要求必须伴随 `Secure`，**删除指令缺失这两个属性会被浏览器直接忽略** —— 表现就是用户点了登出，Cookie 仍在、下次请求依旧登录态。现在删除指令与写入使用**同源属性**（`cookie-secure` / `cookie-same-site` 的配置值）。
  - **缺陷二（清理写错对象）**：`logout(HttpServletRequest request)` 内部用的是线程绑定的 response，而不是由传入的 `request` 推导。当二者不是同一请求时，清理指令会写到**另一个请求**的响应上。Servlet API 无法从请求反查响应，因此修复方式为**校验同一性**：新增 `WebRequestUtils.getResponse(HttpServletRequest)`，若线程绑定的请求不是传入的那一个则返回 `null`（宁可不清理，也不写错对象）。正常 Web 请求下二者本就是同一实例，行为不变。
  - **API 兼容**：`CookieUtil.removeCookie` 的两参/三参重载保留（委托新五参重载，属性取默认值），既有调用方无需改动。
  - **不受影响**：未开启 `enable-cookie` 的项目（纯 token 模式根本不会写/删 Cookie）。
- **新增仓储契约测试（TCK）：同一套 20 个用例跑四个仓储实现**（`single` / `caffeine` / `redis` / `jdbc`）：
  - **为什么要有它**：框架内置四种仓储且鼓励用户自定义实现，而"四个仓储行为一致"此前只靠人工比对。1.5.0 期间已反复出现同一语义在不同仓储下表现不同（过期会话复活、并发上限强度不一、`timeout` 四种语义、共享引用与类型漂移）。现在把契约写成**可执行断言**，新增实现只需继承基类即可获得全部校验。
  - **建立过程中直接抓出两个真实缺陷**：`single` 与 `redis` 的有效性判定**只看存储层 TTL、不看 `loginExpireTime`**，于是"存储层仍有效、但会话已过期"的凭证被判为有效（与 `caffeine` / `jdbc` 口径不一致）；`redis` 的在线列表清理有同一问题，导致在线数虚高。两处均已修复。
  - **如何对真实 Redis 跑**（默认跳过，CI 无 Redis）：设置 `TINY_SECURITY_TCK_REDIS=1`（可选 `_HOST` / `_PORT` / `_PASSWORD` / `_DATABASE`，默认 `127.0.0.1:6379`、db `15`）；测试只清理 `tiny:security:*` 前缀，**不执行 FLUSHDB**。
  - **Jdbc 的一处已知豁免**：并发登录上限的原子性在 Jdbc 上不成立（无法在不改表结构的前提下原子化），TCK 中以**显式声明的豁免**记录，而非让测试静默放过 —— 详见文档 §4.3 第 13 行。
- **修复 `getSubject` 返回共享实例与 `loginId` JSON 往返类型漂移**：
  - `single` / `caffeine` 仓储把对象**引用**存在内存里，`getSubject` 直接返回缓存实例 —— 调用方修改读到的对象（如 `setLoginExpireTime(...)`）会**污染缓存并在后续请求生效**，而 `redis` / `jdbc` 每次反序列化出新对象、不受影响。现在统一返回 `LoginSubject.copy()` 副本，四种仓储语义一致。
  - `loginId` 声明为 `Object`，但 `Long 10001` 经 JSON 往返会被反序列化成 `Integer`（`redis` / `jdbc` 走 JSON），于是 `(Long) subject.getLoginId()` 抛 `ClassCastException`。现在在 `setLoginId` 做反序列化归一化：整型一律归一为 `Long`，字符串与小数类型保持不变。
  - **行为变更**：若此前依赖"修改 `getSubject` 的返回值能持久生效"（仅内存版仓储可能发生），升级后不再生效 —— 这属于修正，不是能力削减。
- **修复 `JsonUtil` 用裸 `ObjectMapper` 带来的两个问题**：
  - **`extraInfo` 里放 `java.time` 类型会让登录直接 500**（`InvalidDefinitionException`）。现在 `ObjectMapper` 调用 `findAndRegisterModules()` 自动注册 JSR-310 等模块，并关闭 `WRITE_DATES_AS_TIMESTAMPS` —— java.time 写成 ISO-8601 字符串（与 Spring Boot 默认 ObjectMapper 一致），便于直接排查 Redis/JDBC 里存的会话内容。
  - **给 `LoginSubject` 加字段在滚动发布期间会变成升级事故**：Jackson 默认 `FAIL_ON_UNKNOWN_PROPERTIES=true`，旧实例读到新实例写入的会话时反序列化失败、`readValue` 返回 null，被当成"会话不存在"而把在线用户**全打成 401**。现在 `LoginSubject` 标注 `@JsonIgnoreProperties(ignoreUnknown = true)`。
  - **约定**：`LoginSubject` **只增字段，不改名不删除**；变更字段语义时请按「新增字段 + 兼容旧字段」的方式演进。
- **修复 `SM3Hash` 哈希失败时静默返回全 0 哈希**：原实现在 `catch (Exception)` 后把预分配的 `byte[32]` 直接当结果返回，调用方拿到一个看起来合法的常量 `00…00`，无法区分"算错了"和"算完了"。现已移除该吞异常分支，失败会正常抛出。
  - 说明：该 `catch` 实际是死代码（`SM3Digest.update/doFinal` 不抛受检异常，且 `source = null` 也不会触发异常，因为字符串拼接容忍 `null`），因此这处改动是**消除隐患**而非修复线上故障。
- **修复自定义 `TinySecurityFacade` Bean 会让 `AuthUtil`（及 `AuthProvider.getSecurityContext()`）整体瘫痪**：
  - **根因**：`AuthUtil` 通过一个静态变量持有门面，而**唯一**的赋值点是 `AuthAutoConfiguration` 里带 `@ConditionalOnMissingBean(TinySecurityFacade.class)` 的 Bean 方法。用户一旦自己声明该 Bean（Spring 用户的本能），框架 Bean 被跳过 → 静态变量永远为 null → `AuthUtil.getLoginId()` 抛 `IllegalStateException`。
  - **修复**：去掉静态门面，`AuthUtil` 改为从当前请求的容器解析 `AuthProvider`。这一改动同时消除了"静态状态可以失同步"这一整类问题。
- **修复 `AuthProvider.getSecurityContext()` 反向依赖静态 `AuthUtil`**：
  - **根因**：作为 Spring Bean 的 `AuthProvider` 依赖了"另一个 Bean 在构造时顺手赋值的静态变量"，导致手工 `new AuthProvider(...)`、单元测试、非 Web 线程都拿不到上下文。
  - **修复**：`AuthProvider` 现在直接持有注入的 `SecurityContextRepository`（`getSecurityContext()` 的能力来自其内部基类 `TinySecurityFacade`），不再经由 `AuthUtil`。新增 5 参构造注入 `SecurityContextRepository` + `AuthorizationInfoGet`，原 3 参构造保留。
- **修复权限注解写在父类/接口上时被直接放行（fail-open）**：
  - **根因**：注解查找用的是 `method.getAnnotation(...)` + `method.getDeclaringClass().getAnnotation(...)`，只认"方法本身 + 方法声明类本身"。而方法注解**不随重写或接口实现继承**，元注解也不会被 `getAnnotation` 解析。于是下列三种写法会被判定成"无注解接口"，授权拦截器**直接放行且不报错**：
    1. 子类**重写**了父类带注解的方法、自己没重新标注；
    2. 注解标在**接口方法**上、实现类方法未标注；
    3. 用**组合注解**（自定义注解上标 `@RequiresPermissions` / `@RequiresRoles` / `@Ignore`）。
  - **修复**：`AnnotationUtils` 的三处查找统一改用 `AnnotatedElementUtils.findMergedAnnotation`，先查方法（沿父类/接口的同名方法上溯）再查声明类，并解析元注解，一次覆盖上述三种写法。
  - **行为变更**：原先漏掉的三种写法现在会生效。副作用是对 `@Ignore` 也一并生效（父类/接口上的 `@Ignore` 在重写/实现后不再被忽略）—— 因 `@Ignore` 是用户显式书写的框架自有注解，按"尊重用户意图"处理。
  - **说明**：`@RequiresPermissions` / `@RequiresRoles` / `@Ignore` 均**不是** `@Inherited`；但"父类标了注解、子类只继承不重写"这一场景**原本就不会漏**（反射拿到的 `Method` 其声明类即父类），不需要改动。

### 🧪 测试补充

- **补齐 4 处此前无覆盖的公开能力**（core +23 例，starter +2 例，总计 315 → 338 / 356）：
  - **`AuthProvider#deleteByToken` 此前 0 覆盖**，现补 7 例：正常删除、只删目标会话不影响同账号其它会话、签名被篡改不得删除、credentials 被替换不得删除、空 token 抛断言异常、畸形 token 返回 false 而非抛异常、未登录态下 `getToken()` 抛 401。
  - **`CookieUtil` 此前无直接测试**（仅被间接覆盖），现补 9 例 —— 重点锁定「删除 Cookie 必须带与写入一致的 Secure/SameSite」，即「登出后仍是登录态」那个缺陷的修复点；另覆盖 URL 编解码往返、非 Web 线程 response 为 null 时静默跳过、空名称不写入。
  - **`TinySecurityHandlerExceptionResolver` 此前无直接测试**，现补 7 例：安全异常接管、非安全异常返回 null 交还 Spring、仅 cause 是安全异常时不接管（有意不做 cause 上溯）、默认优先级为 HIGHEST_PRECEDENCE、优先级可配。
  - **`SpringSecurityEventPublisher` 此前无测试**，现补 2 例：三类事件均被原样转发、底层异常向上传播（不做吞没，否则上层的事件隔离逻辑走不到）。
- **修复两处「空转断言」（写了但实际验证不到东西）**：
  - `AuthProviderCookieTest#shouldLoginWithoutNpeOnNonWebRequestThread` 声称验证「非 Web 线程写 Cookie 不 NPE」，但 `enableCookie` 默认 `false` → **根本没走到写 Cookie**，那条 NPE 回归实际无保护。现已显式开启 Cookie，并做反向验证（把 `CookieUtil` 的 `response == null` 守卫变异为 `false`，该例精确报 NPE 变红）。
  - `AuthAutoConfigurationTest` 的 `assertThat(bean).isInstanceOf(SessionRepository.class)` **恒真**（从容器按该类型取出的对象当然满足该类型）。现改为断言「容器里的 Bean 就是用户自定义的那个实例」（`isSameAs`）。已验证：旧写法下变异也照样通过，新写法下变异即变红。
- **覆盖率**：core 行覆盖率 68.4% → **80.6%**，starter 58.1% → **63.3%**。

### 🧹 清理与收尾

- **删除 `SM3ConvertUtil`（560 行）**：该类仅 3 个方法（`intToBytes` / `byteToInt` / `longToBytes`）被 `SM3` 使用，**其余约 540 行是公开死代码**，且内含 `Math.pow` 做 hex→int（浮点精度）、`byteToString` 符号扩展、`hexStringToBytes("GG")` 静默产出 `0xFF`、`byteConvert32Bytes` 对非 32/33 字节输入越界等一批缺陷。现已把仍需的 3 个转换**内联进 `SM3`** 并整类删除 —— 删掉即修复，不必逐条治理那些死方法。
  - 内联时顺带把实现**直接写成大端**（原先为「先按小端展开 + `back()` 整体逆序」的绕行写法），语义等价且少一次数组拷贝。
  - **SM3 算法字节级不变**：GM/T 0004-2012 标准测试向量 `66c7f0f4…` 与全部 KAT 断言保持通过。
- **删除 `BCrypt.main` 及其 5 处 `System.out.println`**：该方法会把硬编码的示例口令打印到 stdout / CI 日志。同时复核全项目生产代码，`public static void main` / `System.out` / `printStackTrace` 现均为 **0 处**。
  - 与之配套，CHANGELOG 的 1.3.3 段补了一条**勘误** —— 该段此前声称已清理 `main()`/`System.out`，实际漏清了 `BCrypt.main`。保留原记录并加勘误，不做静默改写。
- **删除 `HexUtil.hexToBytes` / `hexToByte`**：全项目无调用方（框架内没有「十六进制字符串 → 字节」的需求），保留无调用方的公开方法等于长期维护一份无人验证的代码。
- **工具类补私有构造函数**：`CommonUtil` / `CookieUtil` / `JsonUtil` / `HexUtil`（`TokenSignUtil` 本就有）。

### 📖 文档修正

- **新增 `AuthProvider.getRawToken()`，`getToken()` 改为返回带前缀值**（P2-7，见下方「缺陷修复」）：README 的 `getToken()` 章节同步说明两者区别，并提示旧行为请改用 `getRawToken()`。
- **修正 README 中无法编译 / 与代码相反的多处示例**（一次性收掉 DOC-2/3/4/5/6/8/11/13/14/15）：
  - `I18nUtils.getMessage(...)` —— **该类全项目不存在**，改为异常自带消息 `e.getMessage()`。
  - `deleteTokenByLoginId(...)` → 真实方法名 **`deleteByLoginId`**。
  - `AuthUtil.getLoginId()` 被描述为「未登录返回 null」—— 与代码**完全相反**（实际抛 `UnAuthorizedException`），已改正并去掉 null 判断写法；同时补上「`AuthUtil` 只适用于持有当前请求的线程」这一边界说明。
  - `PermissionInfoInterfaceImpl` → 真实 SPI 名 **`AuthorizationInfoGet`**。
  - JDK 徽章 `JDK 8+` → **`JDK 17+`**（pom 的 `source/target` 就是 17）。
  - §2.5.1 教用户从 URL 参数传 token，但 `enable-url-token` 默认 `false`、照做必然 401 —— 已加显式警告。
  - 补上 `t_auth_storage.sql` 的位置与导入说明、`login_subject` 为 `varchar(5000)` 的上限提示。
  - 补齐配置项 `banner`（逐项核对 `AuthProperties` 全部 17 个字段后，它是唯一缺失项）。
  - `README.en.md` 补齐边界说明、`@Ignore`、token 传递、异常翻译等章节；英文注释里「`AuthUtil` is a static facade」的过时描述已改正。
  - 移除两处对**不存在的文档**的引用。

- **明确框架边界：不做数据权限与角色继承**（定位决策，非代码变更）：
  - **本框架只做「认证 + 鉴权判定」内核**：身份认证、会话生命周期、注解/URL 鉴权判定、异常翻译、安全默认值与配置校验。
  - **明确不做**：数据范围（行级数据过滤）、角色继承、权限树、菜单/按钮码的数据模型、权限后台管理界面。**这些请在业务项目内实现。**
  - **为什么**：「本人 / 本部门 / 本部门及以下 / 自定义」这类数据范围判定，取决于 `sys_user` / `sys_dept` / `sys_role_dept` 这类**业务表结构** —— 框架要声称支持它，就必须假设一套它并不拥有的数据模型。作为对照：**Spring Security** 的授权止于 `AuthorizationManager` / `GrantedAuthority`，数据过滤明确交给业务；**Shiro** 止于 `Realm` + `WildcardPermission`，角色继承需自行实现 —— **两者都不提供数据范围**。真正带数据范围的是若依（RuoYi）这类 Admin 脚手架，且它是在**业务项目内**实现的。
  - **若强行在框架层做，代价会落在用户身上**：已知唯一可行形态是 `@DataScope(deptAlias=..., userAlias=...)` + ORM 拦截器拼 SQL，即把**表名/列名当字符串**传进拦截器（脆弱 + 注入面）、**绑死具体 ORM**（本框架目前零持久层依赖），且仍覆盖不了非 MyBatis 场景。
  - **对已有用户的影响**：**无**。这是边界声明，不删除任何现有 API —— `AuthorizationInfoGet`（`Set<String>`）与 `@RequiresPermissions` / `@RequiresRoles` 的 SPI 契约均保持不变。
  - **保留项**：「请求级权限缓存」**早已在框架内**（`SecurityContext` 懒加载，每请求每类数据最多查一次 SPI），不受本次边界调整影响。
- **README §2.5.3 把 `SimpleHash` 从「密码哈希」降级为「摘要工具」**（原章节把 MD5/SHA-1 与 BCrypt 并列在"密码哈希"语境下推荐）：
  - 章节标题改为「**摘要算法与密码哈希**」，摘要工具在前、密码哈希在后，并在 `SimpleHash` 示例上方加了显式警告：**它是摘要工具、不是密码哈希算法、请勿用于存储用户口令**，理由逐条写明 —— MD5/SHA-1 已不适合任何安全用途；`iterations` 只是**裸摘要的重复计算链**，不是 PBKDF2/scrypt/Argon2 这类有内存硬度、抗 GPU 暴破的密钥派生函数；构造器允许不传盐（无每用户随机盐）；**没有任何校验 API**，调用方只能自己写 `String.equals`，会重新引入时序侧信道。同时把用户**指引到 `BCrypt`**，并在 BCrypt 段补上正面理由（自带随机盐、work factor 可调、`checkpw` 恒定时间比较）。
  - **顺带修复示例代码无法编译的错误**：该节此前的示例用的是 `new MD5Hash(...)` / `new Sha256Hash(...)` —— 这两个类**在项目中根本不存在**（真实类名是 `SimpleHash`），12 行示例全部无法编译。现已全部换成真实 API，并把 `new SM3Hash(...)` 的示例统一为 `new SimpleHash("SM3", ...)` 写法。
  - 改写后的所有示例已**逐行照抄进临时类、用 JDK 17 实际编译运行通过**后删除，确保文档示例可用。
  - **无代码改动**：`SimpleHash` 与 `SM3Hash` 本身均保留，本次只纠正定位与措辞。
- **CHANGELOG 的 1.3.3 段补勘误**：见上方「清理与收尾」。


### 升级检查清单

- [ ] 若代码依赖 `getToken()` 返回**不带前缀**的裸值：该行为自 `1.5.0` 起改变，**请改用 `getRawToken()`**（`getToken()` 现返回带 `Bearer ` 前缀的完整值，与 `login()` 同形）
- [ ] 把 `tiny-security.jwt-secret` 改名为 `tiny-security.token-secret`（**务必配置固定值**，否则重启后会话全失效、多实例之间互不认可）
- [ ] 删除配置文件中的 `tiny-security.jwt-subject` 与 `tiny-security.jwt-timeout`
- [ ] 删除配置文件中的 `tiny-security.credentials-style`（已失效）
- [ ] 若代码直接使用过 `CredentialsGenUtil` 或 `NanoId`：两者已删除，请自行替换（UUID 一行即可）
- [ ] 若代码引用了 `AuthConsts.JWT_TOKEN_PREFIX`，改为 `AuthConsts.TOKEN_PREFIX`
- [ ] 若直接使用过 `JwtUtil`：该类已删除，请改用 `TokenSignUtil`
- [ ] 若自定义实现了 `SessionRepository`：确认 `save` 在凭证已存在时返回 `false`，不要静默覆盖
- [ ] 通知用户升级后需重新登录（token 格式变更）
- [ ] 若手工注册过安全门面（`new TinySecurityFacade(repo)`）或自定义过 `TinySecurityFacade` Bean：该类已**不是公开 API**（包级私有且移入 `provider` 包），请改用 `AuthProvider`
- [ ] 若代码调用过 `AuthUtil.setFacade(...)` / `AuthUtil.getFacade()`：两者**已删除**，直接移除即可（`AuthUtil` 其余方法无需任何改动）
- [ ] 检查是否依赖 `WebRequestUtils.getToken(request, "token")` 从 `?token=xxx` 取 token —— **该行为已默认关闭**，需要时改用四参重载并传 `enableUrlToken=true`
- [ ] 检查是否用 `SimpleHash("SM3", …)` / `SM3Hash(…, null, …)` 且 `salt` 传过 `null` —— **该路径的哈希值已改变**，存量哈希需重新生成或迁移（详见上文「行为变更」）
- [ ] 检查是否有权限注解/`@Ignore` 写在**父类或接口**上、而方法在子类里被重写或实现 —— 这些注解此前**不生效**（权限注解方向是漏放行，`@Ignore` 方向是没忽略），升级后会生效
- [ ] 检查 `tiny-security.timeout` 是否为正数 —— **`0` 与一切负数（含 `-1`）升级后都会启动失败**；`-1` 曾短暂表示"永不过期"，该语义已取消，需要长会话请改配一个较大的正数（如 `86400`）
- [ ] 使用 `store-type: redis` 的项目：并发上限判定改用 **Lua 脚本（`EVAL`）** 实现原子化，请确认你的 Redis **支持脚本执行** —— 标准 Redis / ElastiCache 均支持；但**不支持 `EVAL` 的代理或兼容服务（如 Twemproxy）会让登录直接失败**。若确实无法使用脚本，请改用 `store-type: single` / `caffeine`（两者同样已原子化）

---

## 1.4.0

> 升级路径：1.3.3 → 1.4.0 ｜ 本次为双 API 语义统一（破坏性变更）

### ⚠️ 行为变更（升级必读）

- **`AuthUtil` / `TinySecurityFacade` 的 `get*` 与 `has*` 系列在未登录/会话失效时统一抛 `UnAuthorizedException`，不再返回 null**：
  - 影响方法：`getSecurityContext` / `getLoginSubject` / `getLoginId` / `getLoginIdAsString` / `getLoginIdAsInt` / `getLoginIdAsLong` / `getRoleSet` / `getPermissionSet` / `hasRole` / `hasAllRole` / `hasAnyRole` / `hasPermission` / `hasAllPermission` / `hasAnyPermission`
  - 此前 `AuthProvider` 系列已抛异常，而 `AuthUtil`/`TinySecurityFacade` 系列返回 null，两套 API 行为不一致；本次统一为"未登录即抛异常"，与 `AuthProvider`、Spring Security 语义对齐
  - **破坏性**：依赖 `AuthUtil.getLoginId()` 等返回 null 进行容错判断（如可选鉴权接口、日志埋点）的代码，升级后将抛 `UnAuthorizedException`，需改为显式捕获或先判断登录状态
- **移除冗余转发类 `SecurityContextUtils`**（原仅转发到 `AuthUtil`，无自有逻辑）：直接使用 `AuthUtil.getSecurityContext()` 等替代。**破坏性**：若外部代码 import 了 `SecurityContextUtils`，请改用 `AuthUtil`。
- **移除冗余转发类 `ThreadLocalSecurityContextHolder`**（原仅封装一个 `ThreadLocal`）：`ThreadLocal` 已内联进 `ThreadLocalSecurityContextRepository`，通过其静态方法 `getContext()` / `setContext()` / `clearContext()` 访问。**破坏性**：若外部代码 import 了 `ThreadLocalSecurityContextHolder`，请改用 `ThreadLocalSecurityContextRepository`。
- **移除冗余抽象 `LocalMapContainer` 接口及其唯一实现 `LocalMapContainerByConcurrentHashMap`**：`LocalTimeCache` 的 `dataMap`/`expireMap` 字段与构造直接使用 `ConcurrentHashMap`（底层本就依赖它，行为不变，删除 `getSource()` 死方法）。**破坏性**：若外部代码直接 new `LocalTimeCache(...)`，参数类型改为 `ConcurrentHashMap<String,Object>` / `ConcurrentHashMap<String,Long>`。
- **`SessionRepository.deleteByLoginId` 返回值语义统一为"操作已执行"（幂等）**：此前 Single/Caffeine 无会话时返回 `true`，而 Jdbc/Redis 返回 `false`，四个仓储行为不一致。本次统一为：**只要操作正常完成即返回 `true`**（无会话可删也算成功，仅异常返回 `false`）。**破坏性**：依赖 Jdbc/Redis `deleteByLoginId` 返回 `false` 判断"该账号无会话"的代码，升级后将收到 `true`，请改用 `countValidOnlineSessions` 判断是否存在会话。

### 升级检查清单

- [ ] 排查代码中所有 `AuthUtil.getLoginId()` / `AuthUtil.getLoginSubject()` / `AuthUtil.getSecurityContext()` / `AuthUtil.getRoleSet()` / `AuthUtil.getPermissionSet()` 及 `has*` 系列的调用点
- [ ] 若存在"未登录也调用上述方法且依赖返回 null"的场景（如未登录可访问的接口里读取当前用户做日志），改为：先 `try { AuthUtil.getLoginId(); } catch (UnAuthorizedException e) { /* 未登录处理 */ }`，或在确信已登录的路径内调用
- [ ] `hasRole` / `hasPermission` 等"判断型"方法：未登录时也会抛异常（不再返回 false）。若希望未登录容错判断，需在调用前确保已登录或显式捕获
- [ ] 全局异常处理器若已处理 `UnAuthorizedException`（默认 `TinySecurityHandlerExceptionResolver` 会转为 401），则无需额外改动

### 新增特性

- **新增按账号查询会话凭证 `getCredentialsByLoginId(Object loginId)`**：返回该账号下全部**有效（未过期）**会话凭证列表，无会话时返回空列表（不返回 null）。
  - 用途：多设备管理（列出账号所有在线设备/会话）、定向下线（配合 `deleteByCredentials` 只踢指定凭证，而非 `deleteByLoginId` 全量踢出）
  - 入口：`AuthProvider.getCredentialsByLoginId(loginId)`；四个内置仓储（single / caffeine / redis / jdbc）均已实现
  - 接口方法声明为 `default`，默认实现抛 `UnsupportedOperationException`：自定义仓储未实现时**显式报错**而非静默返回空列表，同时保持存量自定义仓储的编译兼容
  - ⚠️ 安全提示：凭证等同于会话钥匙，请勿写入日志或返回给前端
- **新增 Caffeine 本地缓存会话仓储**（`store-type=caffeine`）：提供容量上限保护（`caffeine-maximum-size`，默认 10000，近似 LRU 驱逐）与惰性过期驱逐，适合"单机部署、会话量大、需内存上限"场景。
  - **可选依赖**：caffeine 以 `provided` 提供，使用前需自行引入：
    ```xml
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>caffeine</artifactId>
    </dependency>
    ```
  - 过期语义与其它仓储一致：由 `LoginSubject.getLoginExpireTime()` 驱动，续期时重新写入即重置。

### 契约修复

- **`getCredentialsByLoginId` 返回空列表时统一为可变 `ArrayList`**：此前空列表分支返回 `Collections.emptyList()`（不可变），非空分支返回 `new ArrayList<>(list)`（可变），同一份语义却给出不同 mutability（外部 `add/remove` 会爆 `UnsupportedOperationException`）。本次将所有内置仓储的空列表分支统一改为 `new ArrayList<>()`，保证契约一致。

### 测试加固

- 新增 `AuthProviderCredentialsTest`（4 用例）：门面透传、空账号返回空列表、`logout()` 后查询收敛、自定义仓储未实现时抛 `UnsupportedOperationException`
- 四个内置仓储测试各 +2 用例：覆盖多凭证返回、过期凭证排除、空账号可变空列表、返回防御性副本

---

## 1.3.3

> 升级路径：1.3.2 → 1.3.3 ｜ 本次为安全加固 + 正确性修复批次（基于 2026-08-31 安全审计）

### 安全修复

- **恢复 `LoginSubject.toString()` 凭证脱敏**：1.3.2 后 `aae08b7` 曾回退为输出真实 credentials（便于排查），现恢复为固定输出 `credentials=****`，杜绝日志泄露会话凭证；同步恢复并修正 `LoginSubjectTest`。
- **移除可预测凭证生成器**：删除 `snowflake`/`objectid`/`ulid` 三种凭证风格（含时间戳，凭证可被预测/枚举，存在会话冒充风险），仅保留 `uuid`/`random128`/`nanoid`；`CredentialsGenUtil` 对未知风格一律回退 `uuid`。同时删除仅被其引用的 `Snowflake`/`ObjectId`/`Ulid*`/`LocalHostUtil` 实现。
- **URL 参数 token 默认关闭**：新增 `enable-url-token`（默认 `false`），token 默认仅从 header（及开启后的 Cookie）读取，不再回退 URL 参数，避免凭证进入访问日志/Referer。

### Bug 修复 / 正确性

- **滑动续期阈值修正**：`DefaultAuthenticationManager` 续期阈值由 `timeout*0.8` 改为 `timeout*0.2`（剩余 TTL 不足 20% 才续期），消除"会话度过 20% 后每请求触发存储写"的写放大。
- **ThreadLocal 异步残留防御**：`AuthenticationInterceptor.preHandle` 进入时先 `clearContext` 兜底清理一次，降低 Servlet 异步/异常场景下线程回池残留导致的"用户串号"风险。
- **`JsonUtil` 序列化失败显式抛错**：不再静默返回空串，改为抛 `TinySecurityException`，杜绝"登录成功但立即 401"的隐蔽故障。
- **`SingleSessionRepository` 在线索引并发收敛**：list 变更统一由单锁保护，弃用 `put` 整体替换，修复并发计数丢失更新。
- **`login()` 成功路径异常隔离**：成功事件发布移出 try 块，自定义事件监听器抛异常不再被误判为登录失败（仅 WARN）。
- **`getLoginIdAsInt/Long` 异常语义统一**：loginId 非数字时抛 `TinySecurityException`（不再直接抛 `NumberFormatException` 导致 500）。

### API 调整

- `JwtUtil` 新增 `getVerifiedSubject(secret, token)`（验签后取 subject）；原 `getSubject(token)` 不验签，标注 `@Deprecated` 并在 javadoc 中警告；`sign` 增加 payload 空校验。

### 工程清理

- 清理生产类残留 `main()`/`System.out`/`printStackTrace`（`BCrypt`/`SimpleHash`/`SM3Hash`/`SM3ConvertUtil`/banner 输出）；README 版本号同步至 1.3.3 并更新配置说明。
  - **勘误（`1.5.0` 补记）**：本次**实际漏清了 `BCrypt.main`**（含 5 处 `System.out.println`，会把硬编码示例口令打到 stdout/CI 日志），该残留直到 `1.5.0` 才真正删除（见 §1.5.0 的 P3-1）。此处保留原记录并加勘误，不做静默改写。

---

## 1.3.2

> 发布日期：2026-08-27 ｜ 升级路径：1.3.1 → 1.3.2

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 4 项（enable-cookie 开关、jwt-timeout 配置、Cookie 安全属性配置、登出清理浏览器 Cookie） |
| Bug 修复 | 3 项（JWT 公开默认密钥、JWT 过期时间硬编码、非 Web 线程登录 NPE） |
| 安全修复 | 1 项（日志凭证泄露链路） |
| 行为变更 | 2 项（未配置 jwt-secret 时改用随机密钥、Cookie 模式默认关闭） |

### 安全修复

- **移除 JWT 硬编码默认密钥**：此前未配置 `tiny-security.jwt-secret` 时会静默使用一个已在开源文档中公开的内置密钥，且 `LoginSubject.toString()` 会输出会话凭证（日志泄露）——两者组合存在伪造会话的风险。现在 `JwtUtil` 对空密钥直接抛出 `IllegalArgumentException`，不再有任何内置兜底密钥；`LoginSubject.toString()` 对 credentials 脱敏输出。
- **非 Web 线程登录 NPE 修复**：定时任务 / MQ 消费者等未绑定请求上下文的线程调用 `login()` 时，`CookieUtil.setCookie` 不再因 `response` 为 null 抛出空指针，改为跳过 Cookie 写入并正常返回 token。

### Bug 修复

- **JWT 过期时间硬编码 30 天**：`timeout` 配置超过 30 天时会话会在 30 天处静默失效（401）。现新增 `jwt-timeout` 配置（默认 2592000 秒即 30 天），且实际生效值取 `max(jwt-timeout, timeout)`：默认行为不变，超长会话配置不再提前失效。
- **Cookie 生存期与会话不同步**：登录 Cookie 的 maxAge 由硬编码 86400 秒改为与会话 `timeout` 一致，不再出现「Cookie 比会话活得久」。
- **登出未清理浏览器 Cookie**：`logout()` / `logout(request)` 现在会写回 `maxAge=0` 的同名 Cookie，浏览器侧凭证立即失效。

### 新增特性

- **Cookie 模式开关（`enable-cookie`）**：

  ```yaml
  tiny-security:
    enable-cookie: false  # 默认 false；开启后登录写 Cookie、登出清理 Cookie、并允许从 Cookie 读取 token
  ```

- **JWT 自身有效期可配置（`jwt-timeout`）**：

  ```yaml
  tiny-security:
    jwt-timeout: 2592000  # 单位秒，默认30天；实际生效值不低于会话timeout
  ```

- **Cookie 安全属性配置**：

  ```yaml
  tiny-security:
    cookie-secure: false    # 是否仅 HTTPS 传输，默认 false（生产建议开启）
    cookie-same-site: LAX   # SameSite 属性，默认 LAX（可选 STRICT/LAX/NONE，防御 CSRF）
  ```

- **未配置 jwt-secret 时的安全兜底**：启动时自动生成 128 位随机密钥并打印 WARN 日志（提示重启后会话失效、生产环境必须配置固定密钥），替代原先静默使用公开默认密钥的行为。

### ⚠️ 行为变更（升级必读）

- **Cookie 模式默认关闭（`enable-cookie`，默认 `false`）**：此前登录总是写 Cookie、且 token 会自动从 Cookie 中读取；现在默认纯 token 模式（仅 header 与 URL 参数）。**前后端不分离、依赖 Cookie 传递 token 的项目升级后必须显式配置 `enable-cookie: true`，否则登录不再写 Cookie、请求也无法从 Cookie 中取到 token（全部 401）**。
- **未配置 `jwt-secret` 时改用随机密钥**：此前未配置密钥的项目可以跨重启保持会话（因为使用内置固定密钥）；升级后每次重启会话全部失效。**生产环境请务必配置固定密钥**。
- 直接调用 `JwtUtil.sign(null, ...)` / `JwtUtil.getClaims(null, ...)` 的代码将抛出 `IllegalArgumentException`（原先静默使用内置密钥）；`JwtUtil.sign` 新增带 `expireSeconds` 参数的重载，原三参重载保持兼容（默认 30 天）。

### 升级检查清单

- [ ] **依赖 Cookie 传 token 的（前后端不分离）项目：务必配置 `enable-cookie: true`**，否则升级后无法从 Cookie 读取 token
- [ ] 检查是否已配置 `tiny-security.jwt-secret`（未配置的项目重启后会话失效）
- [ ] 如直接使用 `JwtUtil` 工具类，确认未依赖「空密钥走内置默认值」的旧行为
- [ ] 生产环境建议开启 `cookie-secure: true`
- [ ] `LoginSubject.toString()` 不再输出 credentials，如有依赖该输出的日志排查逻辑需注意

---

## 1.3.1

> 发布日期：2026-08-09 ｜ 发布提交：`e54d4e8` ｜ 升级路径：1.3.0 → 1.3.1

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 2 项 |
| Bug 修复 | 1 项（会话调度线程泄露） |
| 破坏性变更 | 3 项（GlobalConfig 移除、AuthProperties 迁移、AES/RSA 工具类删除） |

### 新增特性

- **异常响应 HTTP 状态码强制 200（`force-http-status-200`，`8199d0c`）**：异常响应统一返回 HTTP 200，响应体 `code` 字段仍保留真实业务错误码，前端判错逻辑无需改动。

  ```yaml
  tiny-security:
    force-http-status-200: true  # 默认 false
  ```

  | 配置值 | HTTP 状态码 | 响应体 code |
  |--------|-------------|-------------|
  | `false`（默认） | 真实错误码（401/403/409/500） | 真实业务错误码 |
  | `true` | 统一 200 | 真实业务错误码（不变） |

- **授权检查按注解类型按需调用 SPI（`d4e9e67`）**：接口只标 `@RequiresRoles` 时不再查权限、只标 `@RequiresPermissions` 时不再查角色，单注解场景 Redis 访问减半。

  | 接口注解 | 1.3.0 行为 | 1.3.1 行为 |
  |----------|-----------|-----------|
  | 仅 `@RequiresRoles` | 查角色 + 查权限 | 仅查角色 |
  | 仅 `@RequiresPermissions` | 查角色 + 查权限 | 仅查权限 |

### Bug 修复

- **会话调度线程泄露修复（`68e6c7b`/`3756b8e`）**：`JdbcSessionRepository`、`SingleSessionRepository` 实现 `DisposableBean`，`LocalTimeCache.endRefreshThread()` 改为真正 `shutdownNow()`，解决停机 / DevTools 重启 / 多上下文线程泄露。

### ⚠️ 破坏性变更（升级必读）

- **移除 `GlobalConfig` / `GlobalConfigUtils` 全局静态单例（`776dac9`）**：改为 Spring 依赖注入，配置初始化由 `ContextRefreshedEvent` 监听改为 Bean 构造注入。若业务代码直接调用 `GlobalConfig.getXxx()`，需改为注入对应 Bean。
- **`AuthProperties` 包路径迁移（`776dac9`）**：由 `org.tinycloud.security.AuthProperties`（boot-starter）迁移至 `org.tinycloud.security.config.AuthProperties`（core）。仅需更新 `import` 路径；yml 前缀 `tiny-security` 不变。
- **移除 `AESUtil` / `RSAUtil`（`7cb7eb3`）**：存在硬编码密钥与未用 OAEP 填充等安全隐患，且不属于认证框架职责；保留 BCrypt / SM3 / 摘要算法。如需使用请迁移至 JCA / Hutool / BouncyCastle。

### 架构改进

- **引入 `TinySecurityFacade` 门面模式（`776dac9`）**：`AuthUtil` 作为静态外观 delegate 到 Facade Bean，**用户侧调用方式（`AuthUtil.getLoginId()` 等）完全不变**；内部依赖可测试、可替换。

### 升级检查清单

- [ ] 全局搜索 `GlobalConfig` / `GlobalConfigUtils`，如有引用改为 Spring 注入
- [ ] 全局搜索 `org.tinycloud.security.AuthProperties` 的 import，更新为 `org.tinycloud.security.config.AuthProperties`
- [ ] 全局搜索 `AESUtil` / `RSAUtil`，如有使用迁移至 JCA / BouncyCastle
- [ ] 自定义 `DefaultExceptionTranslator` 时，确认是否需要传入 `forceHttpStatus200`
- [ ] 验证 `AuthUtil` 调用方式未变（正常无需改动）

### 兼容性说明

| 用户侧 API | 兼容性 |
|-----------|--------|
| `AuthUtil.getLoginId()` 等静态方法 | ✅ 完全兼容 |
| yml 配置 `tiny-security.*` | ✅ 完全兼容 |
| `@RequiresRoles` / `@RequiresPermissions` | ✅ 完全兼容 |
| 自定义 `SessionRepository` | ✅ 兼容（建议实现 `DisposableBean`） |
| 直接使用 `GlobalConfig` | ❌ 已移除 |
| 直接使用 `AESUtil` / RSAUtil | ❌ 已移除 |

---

## 1.3.0

> 发布日期：2026-06-08 ｜ 发布提交：`3b381b0` ｜ 升级路径：1.2.7 → 1.3.0

### 类型概览

| 维度 | 内容 |
|------|------|
| 重大重构 | 1 项（springboot3 安全架构整体重构，+5295/-1303，50 文件） |
| 破坏性变更 | 1 项（`addPath` → `includePath` 配置重命名） |
| 其他 | 异常翻译器方案重构、配置类注解位置调整、文档优化 |

### 关键变更

- **springboot3 安全架构整体重构**（`d036e84`，50 文件，+5295/-1303）：推进 springboot3 安全架构重构并补齐回归测试，是 1.3.x 系列的基础性改动。
- **异常翻译器方案重构**（`4debe60`，7 文件）：异常翻译/统一响应方案换实现。
- **配置类注解位置调整**（`5e93688`）：优化代码结构。
- **重构后代码整体优化**（`ecec018`，33 文件）与文档优化（`9fcd7e9`）。

### ⚠️ 破坏性变更（升级必读）

| 变更 | 旧写法 | 新写法 |
|------|--------|--------|
| 拦截路径配置项重命名（`868f4d0`） | `tiny-security.add-path` | `tiny-security.include-path` |
| 路径合并功能 | 无 | 新增 include/exclude 路径合并逻辑 |

> **升级动作**：将 yml 中所有 `add-path` 改为 `include-path`，并确认拦截路径合并行为符合预期。

---

## 1.2.7

> 发布日期：2025-12-11 ｜ 发布提交：`87ea356` ｜ 升级路径：1.2.6 → 1.2.7

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 1 项（`perm-check-enabled` 权限校验开关） |
| 优化/重构 | 3 项（加密类优化、属性与类名标准化） |

### 关键变更

- **新增 `perm-check-enabled` 配置项**（`d9dd06a`）：用于配置是否开启权限校验。
- **优化加密类**（`a7e0f65`，+148/-315）：加密相关实现优化。
- **属性与类名标准化重构**（`388c845` 11 文件、`fd09fbc`）：部分属性和类名更加标准化，提升一致性。

---

## 1.2.6

> 发布日期：2025-12-01 ｜ 发布提交：`0d0950f` ｜ 升级路径：1.2.5 → 1.2.6

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 1 项（控制同时在线人数 / 并发登录限制，多存储演进） |
| 优化 | 4 项（异常处理、banner 配置、拦截器配置内聚、文档） |

### 关键变更

- **控制同时在线人数（并发登录限制）功能演进**（`df03592` / `fe48043` / `9e25724` / `e495d17`）：
  - Redis 版本支持控制同时在线人数
  - 内存版本支持控制同时在线人数（第二版）
  - JDBC 版本第一版实现
- **异常处理优化**（`3e313b1`，8 文件）。
- **banner 配置优化**（`64af3bd`）。
- **拦截器配置内聚**（`8f7ea2a`）：直接在 `AuthAutoConfiguration` 里配置 Interceptor。

---

## 1.2.5

> 发布日期：2025-11-24 ｜ 发布提交：`4693920` ｜ 升级路径：1.2.4 → 1.2.5

### 类型概览

| 维度 | 内容 |
|------|------|
| 优化 | 4 项（拦截器注册机制、权限校验代码、scanKeys、移除过时方法） |
| 文档 | 1 项 |

### 关键变更

- **拦截器注册配置机制优化**（`0abb6de`，5 文件，+93/-141）。
- **权限校验代码与注释优化**（`a772def`）。
- **优化 `scanKeys` 方法**（`e371efa`）：提升 Redis 键扫描效率。
- **修正/移除已过时的方法**（`3820d1d`，-49 行）：清理废弃 API。

---

## 1.2.4

> 发布日期：2025-06-30 ｜ 发布提交：`ff48966` ｜ 升级路径：1.2.3 → 1.2.4

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 1 项（登录时携带扩展信息） |
| 破坏性变更 | 1 项（`PermissionInfoInterface` 签名变更） |
| 优化 | 3 项 |

### 关键变更

- **新增登录扩展信息 API**（`5055c19`，6 文件）：重载 `String login(Object loginId, Map<String, Object> extraInfo)`，可在会话中存储额外的扩展信息。
- **`getLoginId` 方法优化**（`3b4305a`）。
- **Serializable 增加 `@Serial` 注解修饰**（`af0625b`）。
- **springboot3 版本文档更新**（`c2cdc0e`）。

### ⚠️ 破坏性变更（升级必读）

| 变更 | 说明 |
|------|------|
| `PermissionInfoInterface` 签名变更（`ca43439`） | 接口方法改为传入 `LoginSubject`，自定义 `AuthorizationInfoGet` 实现需同步修改方法签名。 |

---

## 1.2.3

> 发布日期：2025-06-11 ｜ 发布提交：`4753fed` ｜ 升级路径：1.2.2 → 1.2.3

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 1 项（BCrypt 算法） |
| 性能优化 | 1 项（无注解时跳过权限校验） |
| 优化 | 5 项 |

### 关键变更

- **新增 BCrypt 算法**（`8965109`，+770 行）：支持 BCrypt 密码哈希。
- **权限校验性能优化**（`562ba6c`）：权限模式为注解时，若类/方法上均无注解则直接返回，避免每次都调用获取权限角色列表。
- **`getLoginId` 增加转换方法**（`d0c5467`）。
- **springboot3 版本初始化入库与 starter 定义调整**（`6b6e005` / `6579fa8` / `72cff54`）：springboot3 不再使用旧方式定义 starter。

---

## 1.2.2

> 发布日期：2025-05-16 ｜ 发布提交：`6be3f66`（另有 `4b6bec0` 重复发布提交）｜ 升级路径：1.2.0 → 1.2.2

### 类型概览

| 维度 | 内容 |
|------|------|
| 新增特性 | 2 项（URL 路径自动权限映射、权限校验类型参数） |
| 破坏性变更 | 1 项（`toke-style` → `credentials-style` 配置重命名） |
| 构建 | 1 项（central-publishing-maven-plugin） |

### 关键变更

- **支持以 URL 路径自动对应权限校验**（`5908275`，3 文件）：URL 路径可自动映射权限校验。
- **增加权限校验类型参数**（`90a094f`，6 文件）：权限校验类型可配置，具体逻辑演进中。
- **权限校验代码抽成公共方法**（`40e4152` / `d35f5b5`）。
- **构建发布流程切换**（`b55fc65`）：新增 `central-publishing-maven-plugin`（OSSRH 于 2025-06-30 停服，迁移至 Central Portal）。

### ⚠️ 破坏性变更（升级必读）

| 变更 | 旧写法 | 新写法 |
|------|--------|--------|
| Token 样式配置项重命名（`05c55b1`，10 文件） | `tiny-security.toke-style` | `tiny-security.credentials-style` |

> **升级动作**：将 yml 中 `toke-style` 改为 `credentials-style`。

---

## 1.2.0

> 发布日期：2025-05-14 ｜ 发布提交：`2651b1d` ｜ 升级路径：1.1.0 → 1.2.0

### 类型概览

| 维度 | 内容 |
|------|------|
| 重大重构 | 1 项（代码完全重构，第一次入库，20 文件 +540/-267） |
| 行为变更 | 2 项（默认 storeType 改为 single、JWT 强制 30 天过期） |
| Bug 修复 | 1 项（未引入 redis 依赖时启动失败） |
| 新增 | 3 项（AuthProvider 公共方法、版本号自动获取、toString） |

### 关键变更

- **代码完全重构**（`dc82ef8` 20 文件 / `3ea5f88`）：springboot3 分支的大范围代码重构与文档更新。
- **`SingleAuthProvider` 代码重构**（`a21a268`，6 文件）与 **AuthProvider 增加公共方法**（`879dd9d`）。
- **默认 `storeType` 改为 `single`**（`944f3af`，7 文件）：⚠️ 默认值变化，使用其它存储（redis/jdbc）的用户需显式配置。
- **JWT 强制 30 天过期**（`8e20648`）。
- **修复启动失败**（`ea7294b`）：解决未引入 `spring-boot-starter-data-redis` 时（`store-type` 非 redis）服务启动失败问题。
- **版本号自动获取工具**（`132199b`，VersionUtil）与 **toString**（`31d70d5`）。
- **优化权限和角色判断方法**（`2de0b45`）。

---

## 版本时间线速览

| 版本 | 日期 | 发布提交 | 一句话主题 |
|------|------|----------|-----------|
| 1.1.0 | 2024-09-06 | `691a4a7` | springboot3 全新版本（基线） |
| 1.2.0 | 2025-05-14 | `2651b1d` | 代码完全重构、默认存储改 single、修 redis 启动失败 |
| 1.2.2 | 2025-05-16 | `6be3f66` | URL 自动权限映射、配置项 `toke-style`→`credentials-style` |
| 1.2.3 | 2025-06-11 | `4753fed` | 新增 BCrypt、无注解跳过权限校验 |
| 1.2.4 | 2025-06-30 | `ff48966` | 登录扩展信息、SPI 接口签名变更 |
| 1.2.5 | 2025-11-24 | `4693920` | 拦截器注册优化、清理过时方法 |
| 1.2.6 | 2025-12-01 | `0d0950f` | 控制同时在线人数（并发登录限制） |
| 1.2.7 | 2025-12-11 | `87ea356` | `perm-check-enabled` 开关、加密类优化 |
| 1.3.0 | 2026-06-08 | `3b381b0` | 安全架构整体重构、`add-path`→`include-path` |
| 1.3.1 | 2026-08-09 | `e54d4e8` | 门面模式重构、线程泄露修复、`forceHttpStatus200` |

---

## 跨版本破坏性变更汇总（升级前必查）

| 配置/API | 变更版本 | 旧 → 新 |
|----------|---------|---------|
| 拦截路径配置 | 1.3.0 | `add-path` → `include-path` |
| Token 样式配置 | 1.2.2 | `toke-style` → `credentials-style` |
| 默认存储类型 | 1.2.0 | 默认改为 `single`（需显式配置其它类型） |
| `PermissionInfoInterface` SPI | 1.2.4 | 方法签名改为传入 `LoginSubject` |
| `GlobalConfig` / `GlobalConfigUtils` | 1.3.1 | 移除，改 Spring 注入 |
| `AuthProperties` 包路径 | 1.3.1 | `org.tinycloud.security` → `org.tinycloud.security.config` |
| `AESUtil` / `RSAUtil` | 1.3.1 | 移除，迁移至 JCA/Hutool/BouncyCastle |
