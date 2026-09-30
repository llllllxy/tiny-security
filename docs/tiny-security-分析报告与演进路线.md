# tiny-security 分析报告与演进路线

> **文档性质**：本文件是 tiny-security 后续演进的**唯一依据文档**（single source of truth）。
> 所有待办、决策、阶段计划都以此文件为准；代码改动后请在本文件内就地更新对应条目的「状态」。
>
> | 项目 | 内容 |
> |---|---|
> | 文档版本 | v1.2 |
> | 分析对象 | 工作区快照：`springboot3` 分支 / 版本号 `1.4.0`（未做 git 校验，见附录 A） |
> | 增量更新 | `1.5.0`：**移除 JWT**，改为 HMAC-SHA256 签名 token；**删除 `credentials-style`，凭证固定为 UUID**；P0-3 修复；四个仓储加凭证碰撞检测（均见 §4.3 IR-1）；**P0-1 / P0-2 修复**——`AuthUtil.has*` 在无注解接口上改为按需懒加载。测试 core 169 / starter 16 全绿 |
> | 模块 | `tiny-security-core`（`tiny-security-core3`）、`tiny-security-boot-starter`（`tiny-security-boot3-starter`） |
> | 分析方式 | **纯静态阅读**（未编译、未运行、未执行任何测试，原因见附录 A） |
> | 覆盖范围 | 60 个生产类、30 个测试类 / 194 个 `@Test`、2 个 pom、README.md / README.en.md / CHANGELOG.md / 资源配置 |
>
> **行号约定**：文中 `文件:行号` 基于上述快照。重构后行号会漂移，**修改代码时请顺手同步该条目的行号**，否则本文件会迅速失效。

---

## 0. 如何使用本文件

1. **先读 §1 和 §2**，5 分钟建立全局判断。
2. **执行时按 §3 的优先级顺序推进**（P0 → P1 → P2 → P3），不要跨级做。
3. **范围与节奏看 §4**（阶段 0/1/2/3），每个阶段有明确的「退出标准」。
4. **动手前先看 §5 的决策项**——有 4 个问题没拍板，做后面的事会白做。
5. **§6 是禁忌清单**，迷茫时优先看这一节。

### 状态取值

| 状态 | 含义 |
|---|---|
| `TODO` | 待处理 |
| `DOING` | 进行中 |
| `DONE` | 已修复并验证 |
| `WONTFIX` | 确认不修（必须在该条目内写明理由） |
| `DEFERRED` | 推迟到指定阶段 |

### 用 grep 统计进度（避免手工维护总览表）

```bash
# 还剩多少 P0 未做
grep -n "^- \*\*状态\*\*：\`TODO\`" -B0 docs/tiny-security-分析报告与演进路线.md

# 按 ID 快速定位
grep -n "P0-1" docs/tiny-security-分析报告与演进路线.md
```

---

## 1. 项目快照

| 维度 | 现状 |
|---|---|
| 定位（自我描述） | 「基于 SpringBoot 的轻量级 Java Web 权限认证框架」 |
| 技术栈 | JDK 17、Spring Boot 3.2.12、jakarta.servlet 6.0、Jackson（**无第三方 JWT / 加密依赖**，token 签名走 JDK `javax.crypto`） |
| 认证模型 | **有状态会话**（每次请求查 Redis / JDBC / 内存）+ `credentials.HMAC-SHA256(credentials)` 签名 token 仅用于携带 `credentials` |
| 授权模型 | 注解（`@RequiresPermissions` / `@RequiresRoles`）或 URL 模式，SPI 为 `AuthorizationInfoGet` 返回 `Set<String>` |
| 会话仓储 | 4 个：`single` / `caffeine` / `redis` / `jdbc` |
| 代码规模 | 生产类 57 个；测试类 27 个 / 178 个用例（`1.5.0` 移除 JWT、`CredentialsGenUtil`、`NanoId` 后的实测值） |
| 文档 | README.md（708 行）、README.en.md（263 行）、CHANGELOG.md（444 行） |
| CI | **无**（无 `.github/`，无任何 workflow） |
| 分支策略 | `master`（SB2 / javax）与 `springboot3`（SB3 / jakarta），靠**手工 cherry-pick** 同步 |

**一句话评价**：认证内核已经成形、仓储层测试相对扎实；但**授权层存在功能性失效**，**加密工具层有一批真实缺陷**，**文档与代码已经脱节到会误导用户的程度**，且**没有任何 CI 兜底**。当前瓶颈不是功能不足，而是「边界不清 + 工程欠账」。

---

## 2. 结论摘要

### 2.1 三个根因

**根因一：定位漂移——一个"有状态会话"库穿着 JWT 的外衣。**
每个请求都要查会话存储，JWT 只用来装一个 `credentials` 字符串。JWT 带来的全是成本：第二条过期时间线（`timeout` vs `jwt-timeout`，还发明了"取二者较大值"的补丁）、密钥管理坑（未配置就随机、重启全掉线）、`Bearer ` 前缀强制解析、签名开销、`credentials` 明文躺在 payload 里可被 base64 解出。**收益为零。** 这是当前概念债务的最大来源。

**根因二：架构在原地打转——三套并行 API + 一个静态全局桥。**
`AuthProvider` / `AuthUtil` / `TinySecurityFacade` 三套入口语义重复，靠 `AuthUtil.setFacade()` 这个静态变量互连。1.3.1 引入门面、1.4.0 统一语义又要删转发类——**三个版本都在重铺同一条管线，产品能力没有前进**。这是"改了很多但感觉没进步"的直接原因。

**根因三：差异化未被回答。**
语义上（`login` / `deleteByLoginId` / `max-concurrent-logins` / `getCredentialsByLoginId`）几乎处处对标 Sa-Token。因此"为什么用 tiny-security 而不是 Sa-Token / Spring Security / Shiro"目前**没有答案**。没有答案的库，功能只会越加越迷茫——因为每个需求都能加，但加完都不构成理由。

### 2.2 最该先做的 7 件事（按顺序）

| 顺序 | 事项 | ID | 为什么排这个位置 |
|---|---|---|---|
| 1 | ~~修 `AuthUtil.hasRole/hasPermission` 无注解接口恒 false 的回归（含测试同步改）~~ ✅ **`1.5.0` 已完成** | P0-1 / P0-2 | 用户最容易踩到的**功能性失效**，且改动小、价值立现 |
| 2 | ~~`random128` 与兜底 JWT 密钥改用 `SecureRandom`~~ ✅ **`1.5.0` 已完成** | P0-3 | **默认路径**下的弱密钥材料；文档还反向保证了安全性 |
| 3 | `JsonUtil` 注册模块 + 容忍未知字段 | P0-4 | 一行代码量级，同时解除「加字段=全员登出」的升级炸弹 |
| 4 | `BCrypt.checkpw` 契约修正（畸形 hash 返回 false） | P0-5 | 登录路径上的 500/DoS 与互操作性风险 |
| 5 | 修 `WebRequestUtils` 便捷重载默认允许 URL 传 token | P0-6 | 公开 API 的安全默认值与框架策略相反 |
| 6 | 修 `SM3Hash` null salt 碰撞 + 静默返回全 0 哈希 | P0-7 | 真碰撞 + 静默失败，两者都违反自身规范 |
| 7 | **加 CI**（`mvn -B verify` + JDK 17/21 矩阵） | ENG-1 | 性价比高于之后所有功能；没有它，前面 6 项修完还会退回去 |

### 2.3 建议的定位（详见 §4.1 / §5）

> 从「又一个 Sa-Token」变成「**Spring Boot 3 上开箱即用的数据权限框架，附带一个极简会话内核**」。

---

## 3. 问题清单

### 3.0 编号与优先级约定

| 前缀 | 含义 |
|---|---|
| `P0-*` | **阻断级**：会造成错误行为或安全弱化，且用户很可能踩到。必须先修 |
| `P1-*` | 高：正确性 / 安全 / 可用性显著受损，或会持续产生维护成本 |
| `P2-*` | 中：健壮性、一致性、性能、边界问题 |
| `P3-*` | 低：清理与卫生 |
| `DOC-*` | 文档与代码不符（含"文档宣传了不存在的类/方法"） |
| `ENG-*` | 工程与流程 |
| `TST-*` | 测试质量与覆盖 |

---

### 3.1 P0 —— 阻断级

#### P0-1 · `AuthUtil.hasRole/hasPermission` 在无注解接口上恒返回 `false`

- **类别**：功能缺陷 / 鉴权 API 静默失效
- **证据**：
  - [`AuthorizationInterceptor.java:84-88`](../tiny-security-core/src/main/java/org/tinycloud/security/interceptor/AuthorizationInterceptor.java#L84-L88)（ANNOTATION 模式且方法无注解 → 直接 `return true`，**不调用授权管理器**）
  - [`DefaultAuthorizationManager.java:49-63`](../tiny-security-core/src/main/java/org/tinycloud/security/authorization/DefaultAuthorizationManager.java#L49-L63)（只在对应注解存在时才查角色/权限集合）
  - [`DefaultAuthenticationManager.java:66-68`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L66-L68)（新建的 `SecurityContext` 只塞了 `loginSubject`）
  - [`SecurityContext.java:19-20`](../tiny-security-core/src/main/java/org/tinycloud/security/context/SecurityContext.java#L19-L20)（`roleSet` / `permissionSet` 默认空集）
  - [`TinySecurityFacade.java:128-151`](../tiny-security-core/src/main/java/org/tinycloud/security/TinySecurityFacade.java#L128-L151)（`getRoleSet()` / `hasRole()` 读的就是这个空集）
- **现象**：接口上**没有**权限注解时，`AuthUtil.hasRole("admin")` / `hasPermission("x")` **永远返回 `false`**（不抛异常），即使账号确实拥有。有注解时也只加载一半：

  | 接口注解 | `hasRole` | `hasPermission` |
  |---|---|---|
  | 无注解 | ❌ 恒 false | ❌ 恒 false |
  | 仅 `@RequiresPermissions` | ❌ 恒 false | ✅ 正常 |
  | 仅 `@RequiresRoles` | ✅ 正常 | ❌ 恒 false |
  | `authorization-enabled: false`（默认） | ❌ 恒 false | ❌ 恒 false |

- **影响**：README §2.3.2 把这两个方法当可用 API 介绍 —— **文档级误导 + 功能性失效**。这是 1.3.1「按注解类型按需调用 SPI」性能优化引入的**回归**，CHANGELOG 只描述了"Redis 访问减半"，没意识到同时抽掉了代码式鉴权 API 的数据来源。
- **修复方案（`1.5.0` 已实施）**：保留"不为注解服务就不做 SPI 调用"的性能设计，但让 `AuthUtil.has*` 在上下文缺数据时**按需从 SPI 懒加载并缓存到本次请求的上下文**（而不是返回空集）。
  - `SecurityContext` 用 `null` 表示「尚未加载」，与「已加载、但确实一个都没有」区分开（新增 `isRoleSetLoaded()` / `isPermissionSetLoaded()`）。`getRoleSet()` / `getPermissionSet()` 对外返回值语义不变（未加载时仍是空集合），因此 `AuthorizationEvaluator` 等既有调用方无需改动。
  - `DefaultAuthorizationManager` 改为**只在真的查了 SPI 时**才写回集合。这是根因所在：此前无论是否查询都无条件 `context.setRoleSet(...)`，把"未加载"直接标成了"已加载"。
  - `TinySecurityFacade` 新增 `(SecurityContextRepository, AuthorizationInfoGet)` 构造重载，`getRoleSet()` / `getPermissionSet()` 在未加载时懒加载并回写上下文；原单参构造保留、行为不变。`AuthAutoConfiguration` 已自动注入 SPI，**starter 用户无感**。
  - 修复后的行为矩阵：

    | 接口注解 | `hasRole` | `hasPermission` | 注解校验期间的 SPI 调用 |
    |---|---|---|---|
    | 无注解 | ✅ 懒加载 | ✅ 懒加载 | 0 次（性能设计保留） |
    | 仅 `@RequiresPermissions` | ✅ 懒加载 | ✅ 复用 | 1 次（权限） |
    | 仅 `@RequiresRoles` | ✅ 复用 | ✅ 懒加载 | 1 次（角色） |
    | `authorization-enabled: false` | ✅ 懒加载 | ✅ 懒加载 | 0 次 |

  - 隐藏收益：`authorization-enabled: false`（**默认值**）下关卡不再恒 false。此前的表格显示该配置下两个方法都失效，是同一根因的另一种表现。
- **状态**：`DONE`（`1.5.0`）

#### P0-2 · 测试固化了 P0-1（改 P0-1 必须先改这三处）

- **类别**：测试缺陷 / 反向锁定 bug
- **证据**：
  - [`DefaultAuthorizationManagerTest.java:133`](../tiny-security-core/src/test/java/org/tinycloud/security/authorization/DefaultAuthorizationManagerTest.java#L133)、[`:156`](../tiny-security-core/src/test/java/org/tinycloud/security/authorization/DefaultAuthorizationManagerTest.java#L156)（两个用例显式断言 `permissionQueryCount == 0` / `roleQueryCount == 0`）
  - [`AuthorizationInterceptorTest.java:54-70`](../tiny-security-core/src/test/java/org/tinycloud/security/interceptor/AuthorizationInterceptorTest.java#L54-L70)（断言无注解放行，但**完全没断言上下文里的 roleSet/permissionSet 被填充**）
  - [`EndToEndFlowTest.java:166-193`](../tiny-security-core/src/test/java/org/tinycloud/security/EndToEndFlowTest.java#L166-L193)（号称端到端，实际**手工 `context.setRoleSet(roles)`** 后再断言 `AuthUtil.hasRole`，绕过了真实链路）
- **影响**：不改这三处，P0-1 修完测试会"变红"，容易被误判为"改坏了"而回滚。
- **判断修正（`1.5.0` 实测）**：原文认为这三处都会"变红"，实测**只有第三处成立**，前两处的定性不准确：

  | 证据 | 实测结论 | 处理 |
  |---|---|---|
  | `DefaultAuthorizationManagerTest:133` / `:156` | 断言的是**授权管理器只为注解查询**，而这恰恰是 P0-1 修复要**保留**的性能设计 —— 修复前后均通过，**不是回归锁** | 不改（断言依然有效，继续锁住性能边界） |
  | `AuthorizationInterceptorTest:54-70` | 只断言"无注解放行"，从未断言集合被填充 —— 修复前后均通过 | **已就地加强**：同时断言「一次 SPI 都不调」+「上下文保持未加载」 |
  | `EndToEndFlowTest:166-193` | 确认存在问题：手工 `context.setRoleSet(roles)` 后再断言 `AuthUtil.hasRole`，绕过了真实链路 | **已重写**：只放 `loginSubject`，由 `AuthUtil.has*` 触发真实懒加载 |

- **真正的回归测试缺口**：原文找错了地方。P0-1 之所以能长期潜伏，根因是**没有任何用例覆盖"上下文未加载"这一状态** —— 所有涉及 `has*` 的测试都先手工 `setRoleSet` / `setPermissionSet`，于是改前改后一样绿。
- **本次新增的回归测试**（`TinySecurityFacadeTest`）：懒加载角色、懒加载权限、每请求每类数据只查一次、已加载则不重复查、未提供 SPI 时行为不变、经 `AuthUtil` 的完整调用路径；`EndToEndFlowTest` 补断言懒加载结果回写上下文。
- **已做反向验证**：把懒加载分支短路后重跑，其中 **5 个用例立刻变红**（`hasRole` 返回 false、SPI 查询次数为 0），确认这些用例真的能抓住 P0-1，而不是"陪着一起绿"。
- **状态**：`DONE`（`1.5.0`）

#### P0-3 · `credentials-style: random128` 不是密码学随机，且兜底 JWT 签名密钥走同一路径（`1.5.0` 已随配置项删除而彻底消失）

- **类别**：安全 / 弱随机
- **证据**：
  - [`CommonUtil.java:54`](../tiny-security-core/src/main/java/org/tinycloud/security/util/CommonUtil.java#L54)：`ThreadLocalRandom.current().nextInt(63)`（非 CSPRNG）
  - `CredentialsGenUtil.generate("random128")` 走上面那个函数（**该类已在 `1.5.0` 删除**，链接随之失效）
  - `AuthProvider` 中未配置密钥时的兜底材料 = `CredentialsGenUtil.generate("random128")`（`1.5.0` 起改为 `CommonUtil.getRandomString(128)`）
  - `CredentialsGenUtil` 的 javadoc 与 README §2.1.3、CHANGELOG 1.3.3 均声称 `random128` **具备密码学随机性**（事实错误）
- **影响**：
  - 会话凭证本身在 JWT payload 中**明文可见**（base64 可解），唯一屏障就是不可预测性 —— 而它被破坏了；
  - 默认路径下**签名密钥的材料质量不合格**（`resolveJwtSecret` 只在 `:460` 打了 WARN）。
- **对照**：`uuid`（`UUID.randomUUID` → SecureRandom）与 `nanoid`（SecureRandom + 拒绝采样，已逐行核实正确）**是真的**；`getRandomString` 的 `nextInt(63)` 边界也**没有 off-by-one**（字母表正好 63 个字符）。问题只在"用了非 CSPRNG"。
- **修复方向**：`random128` 改用 `SecureRandom`；同步修正 README / CHANGELOG 中"密码学随机"的措辞（要么改成事实描述，要么真的做到）。
- **修复记录**（`1.5.0`）：[`CommonUtil.getRandomString`](../tiny-security-core/src/main/java/org/tinycloud/security/util/CommonUtil.java) 改用类级 `java.security.SecureRandom`（`nextInt(str.length())`，取模与字母表长度恒等）。更重要的是**把这条路径整个删掉了**：`credentials-style` 配置项、`CredentialsGenUtil`、`util.idgen.NanoId` 均已删除，凭证固定为 `UUID.randomUUID().toString().replace("-", "")`，签名密钥的兜底材料改为 `CommonUtil.getRandomString(128)`。框架内**不再存在任何非 CSPRNG 的凭证或密钥来源**——不是"把弱的那条修好"，而是"让它无法被选中"。
- **状态**：`DONE`

#### P0-4 · `JsonUtil` 用裸 `ObjectMapper`：既会让登录直接失败，又是滚动发布炸弹

- **类别**：功能缺陷 / 升级兼容
- **证据**：[`JsonUtil.java:24`](../tiny-security-core/src/main/java/org/tinycloud/security/util/JsonUtil.java#L24)（`new ObjectMapper()`，**无 `findAndRegisterModules()`**；全项目 grep 无任何 `registerModule`）
- **两个后果**：
  1. `extraInfo` 里放 `java.time` 类型即**登录 500**：
     ```java
     authProvider.login("u1", Map.of("loginTime", LocalDateTime.now()));
     // → InvalidDefinitionException → TinySecurityException("Json serialize failed")
     ```
  2. 默认 `FAIL_ON_UNKNOWN_PROPERTIES = true` ⇒ **将来给 `LoginSubject` 加一个字段，滚动发布期间旧实例读到新实例写的 Redis/JDBC 会话会反序列化失败 → `readValue` 返回 null → 全员 401**。对一个"会话库"这是升级事故级隐患。
- **修复方向**：注册 JSR-310 模块（或改用 Spring 容器里的 `ObjectMapper`）；`LoginSubject` 加 `@JsonIgnoreProperties(ignoreUnknown = true)`。
- **状态**：`TODO`

#### P0-5 · `BCrypt.checkpw` 契约违反 + 72 字节静默截断 + work factor 取自存储值

- **类别**：安全 / 可用性
- **证据**：
  - [`BCrypt.java:736-748`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L736-L748)（`checkpw`）
  - [`BCrypt.java:652`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L652)（`(password + ...)` → `null` 密码被静默当成字符串 `"null"`，即 `checkpw(null, hashOf("null"))` 返回 `true`）
  - [`BCrypt.java:635-651`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L635-L651)（`salt.charAt(...)` / `substring(...)` 无长度校验）
  - [`BCrypt.java:492-504`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L492-L504)（只读前 72 字节，超出部分**完全不参与**哈希）
  - [`BCrypt.java:649`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L649)、[`:397-401`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L397-L401)（work factor 取自存储 hash，最高 2³⁰；`char64` 差一错误 `>` 应为 `>=`）
- **影响**：
  - 畸形 / 截断 / `$2b$` / `$2y$` 前缀的**存量 hash 会抛异常而不是返回 `false`** → 登录流程表现为 **500 而不是登录失败**，且从其他 bcrypt 实现迁移过来的数据直接不可用；
  - 前 72 字节相同的两个密码**互相可验证通过**；
  - 若存储的 hash 有任何用户可控来源（导入、重置、租户数据），`$2a$30$` 构成**未认证的 CPU 耗尽**向量。
- **修复方向**：畸形输入一律 `return false` + 记录日志；明确支持或明确拒绝 `$2b$`/`$2y$`；`hashpw` 增加 72 字节上限校验；`checkpw` 不泄露 hash 长度。
- **状态**：`TODO`

#### P0-6 · `WebRequestUtils` 的便捷重载默认**允许从 URL 读取 token**

- **类别**：安全 / 默认值不一致
- **证据**：[`WebRequestUtils.java:56-58`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L56-L58)、[`:67-69`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L67-L69)、[`:91-93`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L91-L93)、[`:103-105`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L103-L105)

  ```java
  getToken(tokenName)          → getToken(tokenName, true)          → 第三参 enableUrlToken = true  ❌
  getToken(request, tokenName) → getToken(request, tokenName, true) → enableUrlToken = true  ❌
  ```
- **影响**：1.3.3 刚把"URL 传 token"默认关闭（`AuthProvider` 走 [`resolveEnableUrlToken()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L480-L483) = false，**生产路径是安全的**），但**公开工具类的默认值仍是开**。用户直接调 `WebRequestUtils.getToken(request, "token")` 就把凭证重新暴露到访问日志 / Referer。同一份安全策略在两个入口给出相反默认值。
- **修复方向**：便捷重载的 `enableUrlToken` 默认改为 `false`；或在 javadoc 中显著警告。
- **状态**：`TODO`

#### P0-7 · `SM3Hash` null salt 与字符串 `"null"` **产生相同哈希**；失败时静默返回全 0

- **类别**：安全 / 正确性
- **证据**：
  - [`SM3Hash.java:82`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3Hash.java#L82)：`(source + salt)` —— `salt == null` 时哈希的是 `"passwordnull"`
  - [`SM3Hash.java:79-90`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3Hash.java#L79-L90)：`catch (Exception)` 后**返回预分配的 `new byte[32]`（全 0）**当作合法哈希
  - [`SimpleHash.java:44`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/SimpleHash.java#L44)（SM3 分支同样中招，而 JDK 分支对 null salt 处理是**正确**的）
- **影响**：
  - `salt=null` 与 `salt="null"` 是**真碰撞**（两个逻辑上不同的输入产生同一哈希）；
  - `setSalt(null)` 与不设 salt（默认 `""`）结果也不同；
  - 哈希失败时调用方拿到一个看起来合法的常量 `00…00`，无法区分"算错了"和"算完了"。
- **修复方向**：salt 归一化（null → `""`），并统一盐序为 `H(salt‖source)`（与 JDK 分支对齐）；编码失败改为抛异常。
- **状态**：`TODO`

---

### 3.2 P1 —— 高

#### P1-1 · 自定义 `TinySecurityFacade` Bean 会让 `AuthUtil`（及 `AuthProvider.getSecurityContext()`）整体瘫痪

- **证据**：[`AuthAutoConfiguration.java:256-266`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/AuthAutoConfiguration.java#L256-L266) —— `AuthUtil.setFacade(facade)`（`:260`）是**唯一**赋值点，而该方法带 `@ConditionalOnMissingBean(TinySecurityFacade.class)`（`:257`）。
- **影响**：用户一旦自己声明 `TinySecurityFacade` Bean（Spring 用户的本能），框架 Bean 被跳过 → 静态门面永远为 null → `AuthUtil.getLoginId()` 抛 `IllegalStateException`，**并连带 `AuthProvider.getSecurityContext()` 一起坏掉**（见 P1-2）。
- **旁证**：测试里专门有 `shouldNotOverrideUserDefinedAuthProvider`，却**没有** `TinySecurityFacade` 的对应用例。
- **修复方向**：把静态门面注入改为 `SmartInitializingSingleton` / `BeanPostProcessor` 级别的兜底，或**直接去掉静态门面**（推荐，见 §5 决策 2）。
- **状态**：`TODO`

#### P1-2 · `AuthProvider` 反向依赖静态 `AuthUtil`，靠测试手工注册才跑得通

- **证据**：[`AuthProvider.java:392-399`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L392-L399)（`getSecurityContext()` 调 `AuthUtil.getSecurityContext()`，即一个 Spring Bean 依赖"另一个 Bean 在构造时顺手赋值的静态变量"）
- **旁证**：[`AuthProviderSecurityContextTest`](../tiny-security-core/src/test/java/org/tinycloud/security/provider/AuthProviderSecurityContextTest.java) 必须显式 `AuthUtil.setFacade(...)` 才能让被测方法工作。
- **影响**：手工 `new AuthProvider(...)`（README §2.5.2 风格）、单测、非 Web 线程都会拿不到上下文。
- **修复方向**：`AuthProvider` 直接注入 `SecurityContextRepository`。
- **状态**：`TODO`

#### P1-3 · 异步线程拿不到安全上下文（只修了"残留"，没修"传播"）

- **证据**：[`ThreadLocalSecurityContextRepository.java:17`](../tiny-security-core/src/main/java/org/tinycloud/security/context/ThreadLocalSecurityContextRepository.java#L17)（纯 ThreadLocal）+ [`AuthenticationInterceptor.java:50-55`](../tiny-security-core/src/main/java/org/tinycloud/security/interceptor/AuthenticationInterceptor.java#L50-L55)（1.3.3 加的**入口兜底清理**只解决了"上一请求残留"）
- **影响**：`Callable` / `DeferredResult` / `@Async` / MQ 消费线程里调用 `AuthUtil.*` 会抛 401（或读到错误身份）。1.3.3 的注释也承认没引入全局 Filter。
- **修复方向**：提供 `SecurityContextPropagator` / `TaskDecorator`，覆盖 `@Async`、`Callable`/`DeferredResult`、MQ 消费。
- **状态**：`TODO`

#### P1-4 · 注解只认「方法本身 + 方法直接声明类」，父类/接口上的注解被忽略 → 静默失去保护

- **证据**：[`AnnotationUtils.java:45-65`](../tiny-security-core/src/main/java/org/tinycloud/security/annotation/AnnotationUtils.java#L45-L65)（`method.getAnnotation(...)` + `method.getDeclaringClass().getAnnotation(...)`）
- **影响**：`@RequiresPermissions` **不是** `@Inherited`，因此"基类上标了注解、子类 Controller 继承"这种写法会让授权拦截器判定"无注解"→ **直接放行**。这是安全方向的失败（fail-open）。
- **修复方向**：改用 `AnnotatedElementUtils.findMergedAnnotation`（会沿父类/接口上溯）。
- **状态**：`TODO`

#### P1-5 · Cookie 模式的两个真实缺陷

- **证据**：
  - [`CookieUtil.java:128-137`](../tiny-security-core/src/main/java/org/tinycloud/security/util/CookieUtil.java#L128-L137)（删除 Cookie 只带 `path`/`maxAge=0`/`HttpOnly`，**不带 `SameSite` 也不带 `Secure`**）
  - [`AuthProvider.java:321-326`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L321-L326)（`logout(HttpServletRequest request)` 内部用的是 `WebRequestUtils.getResponse()`，**不是**由传入的 `request` 推导）
- **影响**：
  1. `SameSite=None` 时浏览器要求删除指令同样带 `SameSite=None; Secure`，否则**删除被忽略** → "登出后仍是登录态"；
  2. 非 Web 线程 / 显式传 `request` 的场景下 Cookie **不会被清理**（静默）。
- **旁证**：[`AuthProviderCookieTest`](../tiny-security-core/src/test/java/org/tinycloud/security/provider/AuthProviderCookieTest.java) 只断言了 `maxAge == 0`，未断言属性。
- **状态**：`TODO`

#### P1-6 · 内核不做绝对过期校验，把"会话是否过期"外包给仓储实现

- **证据**：[`DefaultAuthenticationManager.java:53-65`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L53-L65)（只判断"剩余 TTL 是否 ≤ timeout×20%"，**从不判断是否已过期**）
- **影响**：四个内置仓储确实过滤了过期，但 README 明确鼓励用户自定义仓储 —— 一旦漏了这层过滤，**过期会话会被无限续期**（走刷新分支 `setLoginExpireTime(now + timeout)` 把它复活）。安全框架不该把核心判定外包给插件。
- **修复方向**：内核加一次 `expireTime <= now → 401`。
- **状态**：`TODO`

#### P1-7 · 并发登录上限是 check-then-act，且四个仓储强度不同

- **证据**：
  - [`RedisSessionRepository.java:224-254`](../tiny-security-core/src/main/java/org/tinycloud/security/session/RedisSessionRepository.java#L224-L254)（有"先 count 检查 + push 后再查 size 检查"**两道**）
  - [`JdbcSessionRepository.java:230-237`](../tiny-security-core/src/main/java/org/tinycloud/security/session/JdbcSessionRepository.java#L230-L237)、[`SingleSessionRepository.java:230-237`](../tiny-security-core/src/main/java/org/tinycloud/security/session/SingleSessionRepository.java#L230-L237)、[`CaffeineSessionRepository.java:263-270`](../tiny-security-core/src/main/java/org/tinycloud/security/session/CaffeineSessionRepository.java#L263-L270)（**只有第一道**）
- **影响**：并发登录突发时 JDBC/内存版可突破上限；Redis 版存在"两个并发请求各自 push 后都超额、于是都自我移除 → 明明有空位却双双失败"的边缘情形。测试全是串行的。
- **修复方向**：Redis 用 Lua 保证原子；JDBC 用唯一约束/乐观锁；内存版加锁。四个仓储行为必须一致。
- **状态**：`TODO`

#### P1-8 · `timeout <= 0` 在四个仓储里有四种语义；`AuthProperties` 无任何校验

- **证据**：[`AuthProperties.java`](../tiny-security-core/src/main/java/org/tinycloud/security/config/AuthProperties.java)（无 `@Validated` / `@Min`）

  | 仓储 | `timeout = -1` 的行为 |
  |---|---|
  | Single | `NEVER_EXPIRE`，永不过期 |
  | Caffeine | `nanosUntilExpire` = 0 → **立即驱逐** |
  | Redis | `expire(key, -1)` → 异常 → `save` 返回 false → **登录失败** |
  | Jdbc | 写入过去的 `credentials_expire_time` → **立即过期** |
- **影响**：配置错了（`timeout: -1` 是很多同类框架表示"永不过期"的写法）不会有任何提示，行为还因仓储而异。
- **修复方向**：统一语义 + 启动期校验（非正值直接拒绝或统一为"永不过期"）。
- **状态**：`TODO`

#### P1-9 · `LoginSubject` 在 single/caffeine 下是**共享引用**，在 redis/jdbc 下是**反序列化副本**

- **证据**：
  - [`SingleSessionRepository`](../tiny-security-core/src/main/java/org/tinycloud/security/session/SingleSessionRepository.java) / [`CaffeineSessionRepository`](../tiny-security-core/src/main/java/org/tinycloud/security/session/CaffeineSessionRepository.java)（存对象引用，`getSubject` 返回同一个实例）
  - [`DefaultAuthenticationManager.java:63`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L63)（在返回的 subject 上 `setLoginExpireTime(...)` → **直接改写缓存中的共享实例**，多请求并发下有数据竞争）
  - Redis/JDBC 每次 `getSubject` 都是新对象
- **影响**：
  1. 同一份用户代码在 4 种仓储下**语义不同**（改 `LoginSubject` 在内存版会持久生效，在 Redis/JDBC 版不会）；
  2. `loginId` 是 `Object`、`extraInfo` 是 `Map<String,Object>`，JSON 往返后**类型漂移**（`Long 10001L` → `Integer`），`(Long) AuthUtil.getLoginId()` 会 `ClassCastException`；
  3. **全项目没有任何测试做过一次 JSON 往返的 `getSubject`**。
- **修复方向**：统一为"返回防御性副本"；`loginId` 类型契约明确化；补 JSON 往返测试。
- **状态**：`TODO`

#### P1-10 · URL 鉴权模式不看 HTTP Method

- **证据**：[`AuthorizationEvaluator.java:41-50`](../tiny-security-core/src/main/java/org/tinycloud/security/authorization/AuthorizationEvaluator.java#L41-L50)（只用 `request.getRequestURI()` 做 Ant 匹配）
- **影响**："拥有 `GET /user` 读权限"等价于"拥有 `DELETE /user` 权限"。另外它拿的是含 context-path 的 URI，context-path 一改全部权限码失效（fail-closed，安全但难用）。
- **修复方向**：权限码纳入 Method；用 Spring 已解析的 `PathPattern` 替代裸 URI。
- **状态**：`TODO`

#### P1-11 · 事件机制：失败路径监听器异常会顶掉原始异常；成功事件携带完整 token

- **证据**：
  - [`AuthProvider.java:287-295`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L287-L295)（`publishLoginFailure` 在 catch 块内，**未被单独 try/catch 保护** → 监听器抛异常会替换原异常）
  - [`AuthProvider.java:298-302`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L298-L302)（**成功路径已正确隔离**：单独 try/catch + WARN —— 此处无需改）
  - [`AuthProvider.java:299`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L299)（`LoginSuccessEvent` 携带**完整 token**，内含 credentials）
  - [`SpringSecurityEventPublisher`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/event/SpringSecurityEventPublisher.java)（同步 `publishEvent`，慢监听器阻塞请求线程）
- **修复方向**：失败路径同样隔离；`LoginSuccessEvent` 改为携带不可逆标识而非完整 token；发布策略可配置同步/异步。
- **状态**：`TODO`

#### P1-12 · `checkLogin()` 可能抛 `IllegalArgumentException`（→ HTTP 500）而不是 401

- **证据**：[`AuthProvider.java:421-427`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L421-L427)（无 try/catch）→ `checkByCredentials(this.getCredentials())` → 仓储的 `Assert.hasText(credentials, ...)` → `IllegalArgumentException`（**不是** `TinySecurityException`，因此异常解析器返回 null，交给 Spring 默认 500 处理）
- **触发条件**：JWT 验签通过但**不含 `credentials` claim**（例如用同一个 secret 签发的其他用途 token）。
- **对照**：[`isLogin()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L406-L414) 已 catch `Exception` → 返回 false，是正确的。
- **状态**：`TODO`

#### P1-13 · `SimpleHash` 被当作"密码哈希"宣传

- **证据**：[`SimpleHash.java:10-24`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/SimpleHash.java#L10-L24)、README §2.5.3
- **问题**：支持 MD5/SHA-1 为一等算法名；"迭代"只是裸摘要链（**不是** PBKDF2/scrypt/Argon2/bcrypt），无内存硬度、无每用户随机盐（存在免盐构造器）、**没有任何校验 API**（调用方只能自己 `String.equals`，重新引入时序侧信道）。
- **修复方向**：README 中移出"密码哈希"章节，降级为"摘要工具"；密码哈希只保留 BCrypt，并考虑提供 `PasswordEncoder` SPI。
- **状态**：`TODO`

---

### 3.3 P2 —— 中

| ID | 问题 | 证据 | 建议 | 状态 |
|---|---|---|---|---|
| P2-1 | Redis 每次登录都做 O(N) 次 `hasKey`（登录延迟随该账号历史会话数线性增长） | `RedisSessionRepository.java`（`save` 内先调 `countValidOnlineSessions`） | 改为一次 `MGET`/`EXISTS` 批量，或把清理挪到低频任务 | `TODO` |
| P2-2 | `core.properties` 缺失时 `properties.load(null)` 抛 **NPE**（不是被捕获的 IOException） → 容器启动期晦涩失败 | [`VersionUtil.java:22-29`](../tiny-security-core/src/main/java/org/tinycloud/security/util/VersionUtil.java#L22-L29) | 判空 + 给出明确错误信息 | `TODO` |
| P2-3 | `exclude-path:` 写成空值时绑定为 null → 传了含 null 的路径列表 | `AuthProperties` `excludePath` 默认 `{}` | 绑定后归一化 + 启动校验 | `TODO` |
| P2-4 | `getRequest()/getResponse()` catch `Exception` 返回 null，把真实故障静默化 | [`WebRequestUtils.java:29-48`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L29-L48) | 区分"无请求上下文"与"真异常" | `TODO` |
| P2-5 | `refreshByCredentials` 的 false 返回值被忽略 → 存储写失败无感知 | [`DefaultAuthenticationManager.java:64`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L64) | 失败时记 WARN/ERROR | `TODO` |
| P2-6 | `LocalTimeCache` 用 `LocalTimeCache.class` 做锁保护**实例字段**（语义混乱）；已存在 executor 时仍打印 "init successful" | [`LocalTimeCache.java:197-216`](../tiny-security-core/src/main/java/org/tinycloud/security/session/timedcache/LocalTimeCache.java#L197-L216) | 清理锁语义与日志 | `TODO` |
| P2-7 | `getToken()` 返回**不带** `Bearer ` 的裸 JWT，而解码侧强制要求前缀 → 把返回值放回 header 会 401 | [`AuthProvider.java:89-97`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L89-L97) vs [`:78-81`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L78-L81) | 统一前缀语义或放宽解析 | `TODO` |
| P2-8 | `extraInfo` 无大小限制，而 `login_subject` 是 `varchar(5000)` → 超长时登录失败（且失败信息不直观） | [`t_auth_storage.sql:11`](../tiny-security-boot-starter/src/main/resources/sql/t_auth_storage.sql#L11) | 序列化后长度校验 + 明确报错 + 文档写明上限 | `TODO` |
| P2-9 | `cookie-same-site: NONE` + `cookie-secure: false` 无校验/告警（浏览器会直接丢弃 Cookie） | `AuthProperties` / `AuthProvider.resolveCookie*` | 启动期校验或自动强制 Secure + WARN | `TODO` |
| P2-10 | ~~`NanoId` 的 `size` 无上界（`Integer.MAX_VALUE` → OOM）；`randomNanoId(Random, ...)` 公开允许传入弱随机源且无警告~~ —— **`1.5.0` 已随 `NanoId` 整体删除而消失**（凭证固定为 UUID，不再需要 NanoId） | 类已删除 | — | `WONTFIX` |
| P2-11 | token 签名密钥**无最小长度校验**（`token-secret: 123` 也接受，只判非空）。原 `JwtUtil` 的同类问题随 JWT 移除而消失（§4.3 IR-1），但校验缺口本身还在 | [`TokenSignUtil.java`](../tiny-security-core/src/main/java/org/tinycloud/security/util/TokenSignUtil.java) | 弱密钥启动期 WARN + 强制最小长度（如 ≥32 字节） | `TODO` |
| P2-12 | `SM3.iv`/`SM3.Tj` 是 **public static 可变数组**（任何代码可全局污染 SM3 常量）；`SM3Digest` 拷贝构造漏拷 `cntBlock`；`doFinal(out,outOff)` 忽略 `outOff` 且不 `reset()` | [`SM3.java:9-14`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3.java#L9-L14)、[`SM3Digest.java:45-62`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3Digest.java#L45-L62) | 改 `private static final` + 防御性拷贝；补齐拷贝构造与 `doFinal` 语义 | `TODO` |
| P2-13 | jBCrypt 遗留缺陷：`char64` 差一（`x==128` 越界）、不支持 `$2b$`/`$2y$`、`gensalt` 只校验上界、`checkpw` 提前返回泄露 hash 长度；`gensalt` 每次 `new SecureRandom()` | [`BCrypt.java:397-401`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L397-L401)、[`:686-726`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L686-L726) | 随 P0-5 一并处理 | `TODO` |
| P2-14 | 异常消息硬编码中文（`"未登录或会话已失效！"`）而翻译器兜底是英文；无 i18n | [`UnAuthorizedException.java:14-16`](../tiny-security-core/src/main/java/org/tinycloud/security/exception/UnAuthorizedException.java#L14-L16) | 引入 `MessageSource` 或统一为英文 + 由业务侧本地化 | `TODO` |
| P2-15 | `SM3Hash` 提供 `getSource()` 返回明文口令；字段可变非 final（非线程安全） | [`SM3Hash.java:29-51`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3Hash.java#L29-L51) | 去 setter / 去 getSource / 明确不可变 | `TODO` |
| P2-16 | `SM3` 的 public `rotateLeft` 用算术 `>>` 而非 `>>>`（负数返回错值）；`SM3.padding` 的 `8 * in.length` 在 int 内先算后转 long（≥256MB 输入溢出） | [`SM3.java:219-221`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3.java#L219-L221)、[`:185,192`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3.java#L185-L192) | 随"删死代码"一并收敛（见 P3-2） | `TODO` |

---

### 3.4 P3 —— 低 / 清理

| ID | 问题 | 证据 | 建议 | 状态 |
|---|---|---|---|---|
| P3-1 | `BCrypt` 仍保留 `public static void main` + 5 处 `System.out.println`（且会打印硬编码示例口令到 stdout/CI 日志）——**与 CHANGELOG 1.3.3「已清理 main()/System.out」的声明矛盾** | [`BCrypt.java:751-769`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L751-L769)、[`CHANGELOG.md:85`](../CHANGELOG.md#L85) | 删除 | `TODO` |
| P3-2 | `SM3ConvertUtil` 560 行中仅 3 个方法（`intToBytes`/`byteToInt`/`longToBytes`）被 `SM3` 使用，**约 540 行公开死代码**；内含 `Math.pow` 做 hex→int（浮点精度）、`byteToString` 符号扩展、`hexStringToBytes("GG")` 静默产出 `0xFF`、`byteConvert32Bytes` 对非 32/33 字节输入越界等一批缺陷。`HexUtil.hexToBytes/hexToByte` 同样无人调用 | [`SM3ConvertUtil.java`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/sm3/SM3ConvertUtil.java)、[`HexUtil.java`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/HexUtil.java) | **整体删除**（删掉即修复，不必逐条治理） | `TODO` |
| P3-3 | `@Deprecated addPath` 至今未删 | [`AuthProperties.java:85-88`](../tiny-security-core/src/main/java/org/tinycloud/security/config/AuthProperties.java#L85-L88) | 2.0 移除 | `TODO` |
| P3-4 | **拆分包**：`org.tinycloud.security` 与 `org.tinycloud.security.event` 同时存在于 core 与 starter 两个 jar | 两模块包结构 | 2.0 一次性整理 | `DEFERRED` |
| P3-5 | 测试文件重复 import（如 `ThreadLocalSecurityContextRepository` 连续 import 两次） | `EndToEndFlowTest`、`AuthorizationInterceptorTest`、`DefaultAuthorizationManagerTest`、`AuthProviderSecurityContextTest` | 清理 | `TODO` |
| P3-6 | 工具类普遍缺私有构造函数（`CommonUtil`、`HexUtil`、`SM3ConvertUtil` 等） | 各工具类 | 顺手补 | `TODO` |
| P3-7 | 本地 `target/` 残留 1.3.0 的 jar 与**已删除类**（`LocalHostUtil`/`ObjectId`/`LocalMapContainer`）的 javadoc | `tiny-security-core/target/` | `mvn clean`（仅本地，非仓库问题） | `TODO` |

---

### 3.5 DOC —— 文档与代码不符

> 这一节性价比最高：**改文字即可，零风险，收益是用户不再被误导**。建议作为阶段 0 的独立批次一次做完。

| ID | 问题 | 证据 | 状态 |
|---|---|---|---|
| DOC-1 | README **宣传了不存在的类** `MD5Hash` / `Sha256Hash`（12 行示例代码全部无法编译；真实类名是 `SimpleHash`） | [`README.md:613-625`](../README.md#L613-L625) | `TODO` |
| DOC-2 | README 示例用 `I18nUtils.getMessage(...)`，该类**全项目不存在** | [`README.md:505-515`](../README.md#L505-L515) | `TODO` |
| DOC-3 | README 用 `authProvider.deleteTokenByLoginId(...)`，真实方法名是 `deleteByLoginId` | [`README.md:334`](../README.md#L334)、[`:341`](../README.md#L341) | `TODO` |
| DOC-4 | README 称 `AuthUtil.getLoginId()` **未登录返回 null** —— 与 1.4.0 破坏性变更（改为抛异常）和代码**完全相反** | [`README.md:284`](../README.md#L284) | `TODO` |
| DOC-5 | README §2.5.1 教用户"把 token 放在 URL 参数里传"，但 `enable-url-token` 默认 **false** → 照做必然 401，且未提示需开启 | [`README.md:525-543`](../README.md#L525-L543) | `TODO` |
| DOC-6 | README 徽章写 **JDK 8+**，pom 实际 `source/target=17`（README.en 写的是 17） | [`README.md:8-10`](../README.md#L8-L10) vs [`pom.xml:38-40`](../pom.xml#L38-L40) | `TODO` |
| DOC-7 | 引用了**不存在的文档**：`docs/project-analysis-2026-08.md`、`docs/security-audit-and-roadmap-2026-09.md`（`docs/` 目录此前不存在） | [`CHANGELOG.md:91`](../CHANGELOG.md#L91)、[`README.en.md:263`](../README.en.md#L263) | `TODO` |
| DOC-8 | README 残留旧类名 `PermissionInfoInterfaceImpl`（接口早已改名 `AuthorizationInfoGet`） | [`README.md:162`](../README.md#L162)、[`:448`](../README.md#L448) | `TODO` |
| DOC-9 | CHANGELOG 声称已清理 `BCrypt`/`SimpleHash`/`SM3Hash`/`SM3ConvertUtil` 的 `main()`/`System.out`，实际 `BCrypt.main` 还在 | [`CHANGELOG.md:85`](../CHANGELOG.md#L85) vs P3-1 | `TODO` |
| DOC-10 | `README.en.md` 是"精简镜像"但缺少 `@Ignore`、`enable-url-token`、异常处理等章节，且同样引用不存在的 docs | 两份 README 对比 | `TODO` |
| DOC-11 | 未说明 `t_auth_storage.sql` 的位置与导入方式，也未说明 `login_subject` 的 5000 字符上限 | [`t_auth_storage.sql`](../tiny-security-boot-starter/src/main/resources/sql/t_auth_storage.sql) | `TODO` |
| DOC-12 | README §2.5.3 把 `SimpleHash`（含 MD5/SHA-1）列在"密码哈希"语境下推荐 | 同 P1-13 | `TODO` |
| DOC-13 | 缺少一份"配置项全表 + 默认值 + 生效条件"（`AuthProperties` 有 20+ 项，README 只列了一部分） | `AuthProperties` | `TODO` |

---

### 3.6 ENG / TST —— 工程与测试

| ID | 问题 | 证据 | 建议 | 状态 |
|---|---|---|---|---|
| ENG-1 | **完全没有 CI**：无 `.github/`、无任何 workflow。一个要发布到 Maven Central 的双分支库全靠手跑 `mvn test` | 已 glob 确认 | 建 `mvn -B verify` + JDK 17/21 矩阵 + 覆盖率门槛 | `TODO` |
| ENG-2 | 双分支（`master`=SB2/javax、`springboot3`=SB3/jakarta）靠**手工 cherry-pick** 同步，历史上已出现"需备份 tag""合并后要人工确认未误引入 jakarta"等高风险动作；Spring Boot 2.7 上游 OSS 支持已于 2023-11 终止 | [`.workbuddy/memory/2026-08-08.md`](../.workbuddy/memory/2026-08-08.md) | 宣布 SB2 分支 EOL（只留安全补丁），精力回收 | `TODO` |
| ENG-3 | `AuthAutoConfiguration` 用**字段注入**（`@Autowired private AuthProperties`），可测试性差；`@ConditionalOnBean(StringRedisTemplate.class)` 未配 `@AutoConfigureAfter(RedisAutoConfiguration.class)`，存在装配顺序风险 | [`AuthAutoConfiguration.java:113-118`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/AuthAutoConfiguration.java#L113-L118) | 后续重构为构造注入 + 显式排序 | `TODO` |
| TST-1 | **没有任何 MockMvc / 真正跑过拦截器的集成测试** —— 两个"端到端"测试都是手工构造 `SecurityContext` 再存进仓储来**模拟**拦截器。P0-1 这类"拦截器↔门面"回归在结构上根本发现不了 | `EndToEndFlowTest`、`TinySecurityAutoConfigurationTest` | 补 MockMvc 全链路测试（含路径排除、异常翻译） | `TODO` |
| TST-2 | **零测试的生产类**：`TinySecurityHandlerExceptionResolver`、`WebRequestUtils`、`CookieUtil`、`AnnotationUtils`、`VersionUtil`、`CommonUtil`、`HexUtil`、`SpringSecurityEventPublisher`（没有任何用例断言事件真的被发布）、`AuthProperties`（仅 2 项绑定）、以及 **`AuthAutoConfiguration.addInterceptors` 的全部逻辑** | 逐类 grep 确认 | 按 §4.2 补齐 P0 相关部分 | `TODO` |
| TST-3 | **空转 / 永真断言**（抽查代表）：`AuthAutoConfigurationTest.java:96-97` 的 `isInstanceOf(SessionRepository.class)` 恒真；`AuthProviderCookieTest.java:34-43` 名为"验证非 Web 线程写 Cookie 不 NPE"，但 `enableCookie` 默认 false → **根本没走到写 Cookie**（1.3.2 修的 NPE 已失去回归保护）；`CaffeineSessionRepositoryTest.java:91-102` 改的是存进去的同一个对象引用，`refresh` 改成空实现也照样绿；`DefaultExceptionTranslatorTest.java:50-57` 名为"code 缺失兜底"，实际兜底分支从未进入；`DefaultAuthenticationManagerTest.java:86-106` 号称测 `<=` 边界，实际恒小于 | 各测试文件 | 逐个修正为可证伪的断言 | `TODO` |
| TST-4 | **静态状态污染 / 并行不安全**：`AuthUtil.facade` 是全局静态被 6 个测试类写；`AuthAutoConfigurationTest` 建 9 个上下文却**没有 `@AfterEach`**，静态门面最后指向**已关闭的上下文**；全项目无 `junit-platform.properties` / `@ResourceLock`。一旦开启并行或漏写一次 `clearContext()`，就会出现"用户串号"式污染 | 各测试文件 | 去静态化（随 P1-1/P1-2）；或至少加 `@ResourceLock` | `TODO` |
| TST-5 | H2 建表语句**内联复制**在测试里，从不使用随包发布的 `t_auth_storage.sql` → 已发布 SQL 与代码存在漂移风险。`1.5.0` 先补上了漏掉的 `credentials` 唯一约束（碰撞路径这才可测），**整体仍未收敛到"加载真实 SQL 脚本"** | `JdbcSessionRepositoryTest.java:35-44` | 让测试加载真实 SQL 脚本 | `DOING` |
| TST-6 | Redis 仓储测试全 Mockito，无真实 Redis → TTL / 原子性 / 序列化全未验证 | `RedisSessionRepositoryTest` | 引入 Testcontainers 或嵌入式 Redis（至少覆盖 TTL 与序列化往返） | `TODO` |
| TST-7 | 白盒反射测试脆弱：`SingleSessionRepositoryTest` 反射写 `LocalTimeCache.expireMap`；`SessionRepositoryLifecycleTest` 反射读 `executorService` 字段名 | 各测试文件 | 改为通过公开 API 或提供 `isShutdown()` 之类可观测点 | `TODO` |
| TST-8 | **没有仓储契约 TCK**（同一套用例跑 4 个实现）—— 这是防止四仓储再次行为分叉的唯一有效手段 | — | 建 `SessionRepositoryContractTest` 抽象基类 | `TODO` |
| TST-9 | `AuthProvider` 大量公开方法无测试：`getToken(request)`、`getToken()` 前缀校验、`getCredentials()`、`getCredentials(request)`、`deleteByToken`、`logout(request)`、`getLoginSubject`/`getLoginId`/`getLoginIdAsString`/`AsInt`/`AsLong`（**5 个全无**）、`checkLogin()`、`getSecurityContext()` 的 `loginSubject == null` 分支、兜底密钥分支 | `AuthProvider` | 随 P0/P1 修复补齐 | `TODO` |

---

## 4. 演进路线

### 4.1 定位决策（先决策，再排期）

| 方案 | 内容 | 代价 | 结论 |
|---|---|---|---|
| **A. 极简会话内核** | 去掉 JWT（用不透明凭证直传）、四种仓储、注解/URL 鉴权、异常翻译、事件。目标：集成成本 < 10 分钟、零魔法、行为可预测 | 放弃"无状态"卖点（本来也没做到） | ✅ **必做的基础** |
| **B. 完整 RBAC + 数据权限** | 权限树 / 菜单-按钮码、角色继承、**数据范围（本人/本部门/自定义）**、权限缓存 + 变更失效、动态权限刷新 | 工作量最大，但**这是国内生态真正的空缺**（Spring Boot 3 + 无重依赖 + 数据权限，几乎没得选） | ✅ **真正的差异化** |
| **C. 多端 / 多租户 / 多 Realm** | `StpLogic` 式多账号体系、按设备类型分别登录、租户隔离 | 复杂度陡增，与 A 冲突 | ❌ 现阶段不做 |

**推荐：A（1.4.x–1.5 收敛）+ B（1.6–2.0 主攻），明确放弃 C，并明确终止 Spring Boot 2 分支。**

### 4.2 阶段 0 · 止血（目标 1~2 周，只做减法与修错，不加功能）

| 顺序 | 事项 | IDs |
|---|---|---|
| 1 | 修 `AuthUtil.has*` 回归 + 同步改 3 个测试 | P0-1、P0-2 |
| 2 | ~~换 CSPRNG（凭证 + 兜底密钥）并修正措辞~~ ✅ **`1.5.0` 已完成** | P0-3 |
| 3 | `JsonUtil` 注册模块 + 容忍未知字段 | P0-4 |
| 4 | `BCrypt` 契约修正 | P0-5、P2-13 部分 |
| 5 | `WebRequestUtils` 默认值 | P0-6 |
| 6 | `SM3Hash` null salt + 失败不再静默 | P0-7 |
| 7 | 删死代码与违规残留 | P3-1、P3-2、P3-5、P3-6 |
| 8 | **文档纠错一次性做完** | DOC-1 ~ DOC-13 |
| 9 | **加 CI** | ENG-1 |

**退出标准**：CI 绿灯；P0 全部 `DONE`；README 中的每条 API 示例都能实际编译通过。

### 4.3 阶段 1 · 把「会话内核」做扎实（1.5）

#### IR-1 · 移除 JWT，改为 HMAC 签名 token（`1.5.0` 已完成）

**决策**（对应 §5 决策 1，已拍板：**移除**）：本框架是**有状态会话**，每个请求无论如何都要查一次会话仓储，JWT「无状态自证」的收益根本兑现不了；而它的成本是实打实的。逐条核对 JWT 到底提供了什么：

| JWT 声称提供的 | 在本框架里的实际价值 |
|---|---|
| 防伪造 | **部分有效**。凭证走 `UUID.randomUUID`（SecureRandom，122 bit），本就不可能猜中，签名纯属冗余；只有历史上的 `random128`（当时非 CSPRNG）场景下签名才真的在兜底——而这个洞已在 P0-3 补上，且 `credentials-style` 已在 `1.5.0` **整体删除**，凭证不再有第二种可能 |
| 防撞 token | **完全没有**。仓储的 key 恒为 `credentials`，两个相同的 credentials 会覆盖同一条记录，但两个 JWT 看上去完全不同——碰撞被签名**掩盖**了，签名在这里是负价值 |

**token 形态**：

```
token = "Bearer " + credentials + "." + base64url(HMAC-SHA256(credentials, secret))
```

- 新增 [`TokenSignUtil`](../tiny-security-core/src/main/java/org/tinycloud/security/util/TokenSignUtil.java)，只用 JDK 的 `javax.crypto.Mac` 与 `MessageDigest.isEqual`（常量时间比对），**约 150 行含注释**。
- `credentials`（uuid / random128 / nanoid）与 base64url 的字母表都不含 `.`，故按**最后一个** `.` 切分即可；格式非法一律返回 `null` → 401，不抛异常穿透。
- **收益**：删掉 `java-jwt` 依赖（pom 里 `jwt.version` 与 dependencyManagement 条目一并删除）；删掉 payload 编解码；删掉**第二条过期时间线**（原 `jwt-timeout` 与会话 `timeout` 取较大值的语义陷阱）；token 里**没有算法字段**，算法在代码里写死 `HmacSHA256`，`alg=none` / 算法混淆风险面归零。
- **配置**：`tiny-security.jwt-secret` → `tiny-security.token-secret`（本就是破坏性变更，顺带改名以免误导）；`jwt-subject` / `jwt-timeout` **直接删除，不留兼容垫片**。
- **API**：`AuthConsts.JWT_TOKEN_PREFIX` → `TOKEN_PREFIX`（前缀保留，值仍为 `"Bearer "`）；`AuthProvider.getCredentialsByToken(String)` **保留原名**，内部由「解 JWT」换成「验签后取 credentials」。

**同时完成的三项加固**：

- **凭证碰撞检测**：四个仓储的 `save` 从「静默覆盖」改为「不存在才写入」——`single` 用 `LocalTimeCache.setObjectIfAbsent`（`ConcurrentHashMap.putIfAbsent`）、`caffeine` 用 `asMap().putIfAbsent`、`redis` 用 `setIfAbsent`、`jdbc` 由 `credentials` 唯一约束拦下并翻译成明确的 ERROR 日志 + `save=false`。碰撞概率约 2⁻¹²²，正常永远不触发；**一旦触发即说明随机源异常或有人在构造会话固定攻击，必须失败而不是覆盖掉别人的会话**。
- **TST-5 部分**：`JdbcSessionRepositoryTest` 的内联建表语句此前漏了 `credentials` 唯一约束（正是 TST-5 担心的漂移），已补齐，碰撞路径这才真正可测。
- **删除 `credentials-style`，凭证固定为 UUID**：原 `CredentialsGenUtil` 支持 `uuid` / `random128` / `nanoid` 三种风格，而它的全部价值就是"让用户挑一个随机源"——这是一个**只有下行风险的选择**：历史上前三种风格（snowflake / objectid / ulid）就因为可预测被删过一轮，`random128` 又因非 CSPRNG 被修过一轮（P0-3）。现在固定为 `UUID.randomUUID().toString().replace("-", "")`，并删除 `CredentialsGenUtil`、`util.idgen.NanoId` 及 `tiny-security.credentials-style` 配置项。
  - **对绝大多数用户零影响**：`uuid` 本来就是默认值，删除配置项后凭证格式**逐字节不变**。
  - 收益：框架内不再存在任何非 CSPRNG 的凭证来源；配置面少一个"能被配坏"的项；少 3 个类（`NanoId` 的 `size` 无上界等 P2-10 问题一并消失）。

**验证**：`mvn -B clean test`（JDK 17）core 175 / starter 15 全绿。

#### 剩余事项

| 顺序 | 事项 | IDs |
|---|---|---|
| 1 | ~~决定 JWT 去留~~ ✅ 已决定：**移除**（见上） | — |
| 2 | `SecurityContext` 懒加载 + 请求级缓存（治 P0-1 的类根因） | P0-1（收尾） |
| 3 | 异步上下文传播 | P1-3 |
| 4 | 绝对过期校验下沉内核；并发上限改原子实现 | P1-6、P1-7 |
| 5 | 静态门面去化（`AuthUtil` 与 `AuthProvider` 解耦） | P1-1、P1-2 |
| 6 | 注解查找沿父类/接口上溯 | P1-4 |
| 7 | Cookie 登出与 SameSite 语义修正 | P1-5 |
| 8 | 仓储契约收紧 + **建 TCK** | P1-9、TST-8、TST-5、TST-6 |
| 9 | 事件机制修正 | P1-11 |
| 10 | 补 MockMvc 全链路集成测试 | TST-1、TST-2 |

**退出标准**：4 个仓储通过同一套契约测试；MockMvc 全链路测试覆盖 认证→授权→异常翻译 三条主路径；`AuthUtil`/`AuthProvider` 在手工 `new` 与自定义 Bean 场景下都可用。

### 4.4 阶段 2 · 做深授权（1.6 → 2.0，真正的护城河）

| 顺序 | 事项 | 说明 |
|---|---|---|
| 1 | `AuthorizationInfoGet` 从「`Set<String>` 裸集合」升级为结构化 `AuthorizationModel`（角色 + 权限码 + 数据范围 + 权限版本号），保留旧 SPI 适配器做兼容 | 这是产品级能力的地基 |
| 2 | **权限缓存与失效**：请求级缓存（必做）+ 可选短 TTL 本地缓存 + `refreshPermission(loginId)` 主动失效钩子 | 当前 README 说"框架不做缓存，请自行处理"，等于把最麻烦的部分推给用户，也放弃了产品价值 |
| 3 | **数据权限**：`@DataScope(deptAlias=..., userAlias=...)` + MyBatis/JPA 拦截器 | **最有可能"别人没有"的能力** |
| 4 | URL 模式补 HTTP Method 与 `PathPattern` 匹配 | P1-10 |
| 5 | 可选：登录失败次数限制/锁定（现在只发事件不消费）、CSRF token 支持 | 补齐安全闭环 |

**退出标准**：能在一个真实中后台项目里，用本框架实现"菜单/按钮权限 + 数据范围过滤"，且不依赖任何额外框架。

### 4.5 阶段 3 · 工程与生态（贯穿）

- 拆分包整理（P3-4，2.0 一次性做）。
- `docs/` 真正建起来并长期维护（DOC-7 已由本文件部分解决）。
- SB2 分支宣布 EOL（ENG-2）。
- 版本与发布流程：CHANGELOG 与本文件的状态表保持同步。

---

## 5. 需要拍板的决策

> 原为 4 个问题；**决策 1 已于 `1.5.0` 拍板并落地**（见 §4.3 IR-1），剩余 3 个仍需回答。

| # | 决策 | 我的建议 | 理由 |
|---|---|---|---|
| 1 | ~~**会话是有状态还是无状态？JWT 留不留？**~~ ✅ **已拍板：有状态，移除 JWT**（`1.5.0` 已落地，见 §4.3 IR-1） | **有状态**；因此 **JWT 应被移除**（或降级为可选兼容模式，`token-style: opaque` 设为默认） | 既然每请求都查存储，JWT 只贡献成本（第二条过期线、密钥坑、`Bearer ` 强制、签名开销）。现在这种"伪无状态"是概念债的源头 |
| 2 | **三套 API 面怎么收敛？** | 保留 `AuthProvider`（唯一实例门面）+ `AuthUtil`（静态便捷外观，但**不再依赖可变静态全局**），**删除 `TinySecurityFacade` 的公开性**（降为内部实现） | 现在三套语义重复且靠静态桥互连，是 P1-1/P1-2/TST-4 的共同根因 |
| 3 | **授权做多深？** | 押注"**角色继承 + 数据范围 + 权限缓存**" | 只做"注解 + 权限码"的话，与 Sa-Token 的差异只剩体积；做深才有不可替代性 |
| 4 | **是否继续维护 Spring Boot 2 分支？** | **终止** | 双分支手工 cherry-pick 是持续性精力消耗，而 SB2 上游早已 EOL |

**目标用户判断**："想要 Spring Security 之外轻量方案的人"已被 Sa-Token 满足；"国内中后台管理系统"才是既有痛点（数据权限）又有量的市场。

---

## 6. 明确不做的事（迷茫时的禁忌清单）

- ❌ **不要再给 `AuthUtil` / `AuthProvider` / `TinySecurityFacade` 加第四个入口**，也不要再"统一一次语义"。先让现有三套收敛成两套。
- ❌ **不要再加回 `credentials-style`**。`1.5.0` 已把它连同 `CredentialsGenUtil` / `NanoId` 整体删除，凭证固定为 `UUID.randomUUID().toString().replace("-", "")`。历史已三次证明这条路上全是坑（snowflake / objectid / ulid 因可预测被删，`random128` 因非 CSPRNG 被修）——**凭证生成器不是配置项，是安全基线**。
- ❌ **不要为了"看起来完整"再加 `AESUtil` / `RSAUtil` 这类不属于认证框架职责的工具**（1.3.1 删得对，不要回退）。
- ❌ **不要继续自研密码学**：SM3 维护了两套实现（`SM3`+`SM3ConvertUtil` 与 `SM3Digest`）、jBCrypt 移植版、一堆十六进制转换器。密码哈希只留 `BCrypt`（或改用成熟库），摘要算法用 JDK + 一个成熟库，把自研密码学面积压到接近零。
- ❌ **不要在补齐 CI、集成测试、文档真实性之前发新功能版本** —— 现在每加一个特性，都在给 §3.5/§3.6 的欠账加息。
- ❌ **不要把"框架不做 X，请自行处理"当成设计**（缓存、i18n 都这么写过）。要么提供，要么在文档里明确"不支持"并给出替代方案。

---

## 7. 本文件的维护约定

1. **修完一条就改状态**：`TODO` → `DONE`，并在该条目末尾追加一行 `- **修复提交**：<commit>`（便于回溯）。
2. **不修的要写明理由**：状态改 `WONTFIX` 并补一行理由，不要直接删除条目。
3. **行号漂移**：改动涉及某条目引用的文件时，顺手更新该条目的行号。
4. **新增问题**：按前缀规则编号（如新的安全问题 → `P0-8`/`P1-14`），不要复用已删编号。
5. **每完成一个阶段**：在 §4 对应小节末尾追加"实际完成情况与偏差"，供下一次决策参考。
6. **每次发版**：检查 §3.5（DOC）是否有新的"文档与代码不符"，这是最容易随代码漂移的一类。

---

## 附录 A · 分析边界与未验证事项

**必须声明**：本次分析所在的执行环境 shell 不可用（`pwsh` 全部以 `0xC0000142` — DLL 初始化失败 — 退出），因此：

- ❌ **未执行 `mvn compile` / `mvn test`**；
- ❌ **未运行任何单元测试**，标注为"空转/永真断言"的用例（TST-3）是**基于断言语义与代码路径的判断**，不是运行结果；
- ❌ **未做 git 校验**，因此无法给出精确的分析 commit hash；
- ✅ 所有结论来自**逐文件静态阅读**，并对下列内容做了交叉核对：Spring `InterceptorRegistration` 源码（确认 `excludePathPatterns` 对空数组不会抛异常）、Jackson 默认配置、`BCrypt`/`NanoId`/`SM3` 的逐行实现、README/CHANGELOG 中每条 API 引用的类与方法是否真实存在（用 grep 逐个确认）。

**建议**：等 CI 建好后（ENG-1），把 TST-3 里每一条都补一个"能证伪"的测试，用运行结果替换本文档中基于阅读的判断。

---

## 附录 B · 已确认**没有问题**的部分（勿误改）

以下结论来自逐行核对，**这些地方是好的，重构时不要"顺手改掉"**：

| 项 | 结论 |
|---|---|
| ~~`NanoId` 的随机性~~（`1.5.0` 已删除该类） | 删除前经核实**确实密码学安全**：`SecureRandom` + 拒绝采样（`bytes[i] & mask`），对默认 64 字符字母表映射均匀、无取模偏差；`INSTANCE` 通过 enum 安全发布。它被删**不是因为不安全**，而是因为"可选的凭证风格"这个设计本身没有必要 |
| `uuid` 凭证 | `UUID.randomUUID()` 走 `SecureRandom`，安全 |
| SM3 摘要内核 | 符合 GM/T 0004-2012：IV / Tj / FF / GG / P0 / P1 / 消息扩展 / 填充均正确；填充边界（0/55/56/57/63/64/119/120 字节）已解析验证；KAT 已由 `SM3HashTest` 锁定。**所有 SM3 问题都在外围 API，不在算法本身** |
| `BCrypt` 的移植保真度 | 是 jBCrypt 0.4 的忠实移植（`P_orig`=18、`S_orig`=1024、`base64_code`=64、`index_64`=128、EksBlowfish 一致）；盐用 `SecureRandom`；`checkpw` 的比较**确实是恒定时间**（比上游的 `String.equals` 更好） |
| ~~`JwtUtil` 的算法锁定~~ → `TokenSignUtil` | 原 `JwtUtil` 用 `JWT.require(Algorithm.HMAC256(...))`，**不存在 `alg=none` / 算法混淆绕过**。`1.5.0` 换成自实现 HMAC 后，算法在代码里写死 `HmacSHA256`、token 里**根本没有算法字段**，该类风险面归零；密钥为空时仍 fail-loud |
| `JsonUtil` 的反序列化安全 | 未开启 Jackson 默认类型信息，**不存在多态 gadget RCE**；`writeValueAsString` 是 fail-loud 的（失败抛 `TinySecurityException` 而非静默返回空串） |
| `CommonUtil.getRandomString` 的取模 | `nextInt(63)` 与 63 字符字母表**精确对应，没有 off-by-one**。问题只在"用了非 CSPRNG"（P0-3），不在取模。`1.5.0` 已换 `SecureRandom`，取模改写为 `nextInt(str.length())`，与字母表长度恒等 |
| `AuthProvider.login` 的事件隔离 | **成功路径已正确隔离**（[`:298-302`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L298-L302) 单独 try/catch + WARN）。只有失败路径未隔离（P1-11） |
| `AuthorizationInterceptor` 对 `@Ignore` / OPTIONS 的处理 | 两个拦截器对 `@Ignore` 与 OPTIONS 的处理一致，逻辑正确 |
| `JdbcSessionRepository` 的表名白名单 | `^[a-zA-Z_][a-zA-Z0-9_.]*$` 校验有效，**杜绝了表名 SQL 拼接注入**；相关测试完备 |
| 四个仓储的过期过滤 | 内置四个仓储**都**正确过滤了过期会话（问题在于内核没有兜底，见 P1-6） |
