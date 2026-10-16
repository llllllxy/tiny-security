# tiny-security 分析报告与演进路线

> **文档性质**：本文件是 tiny-security 后续演进的**唯一依据文档**（single source of truth）。
> 所有待办、决策、阶段计划都以此文件为准；代码改动后请在本文件内就地更新对应条目的「状态」。
>
> **快速上手**：换机器或新接手请看 [`tiny-security-开发交接与进度速览.md`](./tiny-security-开发交接与进度速览.md)
> —— 那份是"怎么恢复干活"（环境准备、已完成批次、工作方式约定、别踩清单）；本文是"为什么这么改"的完整论证。
>
> | 项目 | 内容 |
> |---|---|
> | 文档版本 | v1.7 |
> | 分析对象 | 工作区快照：`springboot3` 分支 / 版本号 `1.4.0`（未做 git 校验，见附录 A） |
> | 增量更新 | `1.5.0`：**移除 JWT**，改为 HMAC-SHA256 签名 token；**删除 `credentials-style`，凭证固定为 UUID**；P0-3 修复；四个仓储加凭证碰撞检测（均见 §4.3 IR-1）；**P0-1 / P0-2 修复**——`AuthUtil.has*` 在无注解接口上改为按需懒加载；**P0-4 修复**——`JsonUtil` 注册 JSR-310 模块、`LoginSubject` 容忍未知字段；**P0-5 定级修正**——`BCrypt` 实为原样引入、零引用的第三方工具类，降级合入 P2-13 并判定 `WONTFIX`（原条目中"72 字节截断""work factor 取自存储值"两条为算法规格误报）；**P0-6 修复**——`WebRequestUtils` 便捷重载默认不再从 URL 读 token；**P0-7 修复**——`SM3Hash` 的 `salt=null` 归一化为空串（消除真碰撞）、失败不再静默返回全 0；**ENG-1 完成**——建立 GitHub Actions CI（JDK 17/21 矩阵 + JaCoCo 覆盖率门槛），建立过程中发现并修复了 `mvn verify` 无法在 CI 运行（GPG 插件绑定 verify）与 JDK 21 下 `byte-buddy` 依赖冲突两个问题，后者通过 `import` `spring-boot-dependencies` BOM 结构性解决；**P1-1 / P1-2 修复**——`AuthProvider` 收敛为**唯一实例门面**（继承降为包级私有内部实现的 `TinySecurityFacade`），`AuthUtil` 去掉 `setFacade`/`getFacade` 与可变静态全局，改为从**当前请求的 `WebApplicationContext`** 解析 `AuthProvider`（用 `findWebApplicationContext` 并区分「多个候选 Bean」的报错）；**P1-4 修复**——`AnnotationUtils` 的三处注解查找改用 `AnnotatedElementUtils.findMergedAnnotation`，修掉「注解写在父类/接口上、方法在子类被重写或实现时被判定为无注解接口而**直接放行**」的 fail-open（原条目对触发条件的描述已实测修正）；**P1-3 定级修正**——「异步线程拿不到安全上下文」判定为**使用方式问题而非框架缺陷**，不做自动传播（线程绑定上下文切线程即失效，与 `SecurityContextHolder` 同构；Spring Security 亦只提供可选的 `DelegatingSecurityContextAsyncTaskExecutor`），原「修复方向」中 MQ 传播不可行、且只传播 `SecurityContext` 并不足以让 `AuthUtil` 工作；**P1-6 / P1-8 修复**——内核补上绝对过期校验（此前已过期会话因「剩余 TTL ≤ 阈值」恒成立而被**无限复活**），`timeout` 非正值在四仓储语义各异的问题按「`-1` 统一为永不过期、其余装配期拒绝」收敛（顺带修掉 Caffeine 的 `Long.MAX_VALUE * 1e6` 溢出，以及 Redis 续期路径 `SETEX` 拒绝 `-1` 导致的续期静默失败 —— 后者系**真实 Redis 实测**才发现，本条最初的判断曾把 Redis 登录路径误判为"登录失败"，已在 P1-8 条目内勘误；因类路径无 JSR-380 校验器，校验用显式代码而非 `@Validated` 以免静默空转；**`timeout` 取值语义最终收敛为「只允许正数」**——开发期间曾实现过 `-1` = 永不过期，因收益存疑、两套过期口径会分叉、且在续期处留下"写成过去时间"的地雷而整体推翻，四个仓储的永不过期分支随之删除）；**P1-7 修复（3/4）**——并发登录上限改为原子实现：Redis 用 Lua 脚本把"判上限 + 入列 + 设 TTL"合并为一次原子执行，Single / Caffeine 把 count 挪进已有的 `onlineLock`，并补上本仓库**首批并发测试**；实测修复前"上限 1 时 4 个并发登录全部被拒"、JDBC"上限 3 时 16 个并发全部成功"，修复后三个仓储恰好放行上限个；JDBC 残余（需改表结构才能真正闭合，三个免改表候选方案已实测否决）另列 §4.3 第 13 行；**P1-11 修复（1/3）**——登录**失败路径**的事件发布补上独立 try/catch + WARN，此前监听器抛出的异常会**顶掉登录失败的真实异常**（成功路径本就已隔离），另两条（成功事件改带不可逆标识、发布策略可配异步）判定为公开 API 变更/新特性、留待阶段 2；**P1-13 修复**——README §2.5.3 把 `SimpleHash` 从「密码哈希」降级为「摘要工具」并加显式警告 + 指引到 `BCrypt`，顺带修掉 DOC-1（该节示例用的 `MD5Hash`/`Sha256Hash` 是**不存在的类**，12 行示例全部无法编译，已换成真实 API 并逐行编译验证通过）、DOC-12。另：**P1-14 修复**——`AuthProvider.refreshByCredentials(credentials, subject)` 此前只延长**存储层 TTL**、从不推进 `subject.loginExpireTime`，与内核的绝对过期校验形成两套分叉口径（表现为续期「没生效」；实测在 `single` 仓储下 `getSubject` 直接返回 `null`，会话根本读不回来）。现按方案 A 让两者口径合一。测试 core 309（含 20 个按需跳过的 Redis 契约用例）/ starter 16 全绿（JDK 17 与 21 均通过） |
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
| 代码规模 | 生产类 58 个；测试类 37 个 / 309 个用例（`1.5.0` 实测值，含本仓库首批并发用例） |
| 文档 | README.md（708 行）、README.en.md（263 行）、CHANGELOG.md（444 行） |
| CI | ✅ GitHub Actions（`.github/workflows/ci.yml`）：JDK 17/21 矩阵，`mvn -B verify -Dgpg.skip=true` + JaCoCo 覆盖率门槛（`1.5.0` 由 ENG-1 建立） |
| 分支策略 | `master`（SB2 / javax）与 `springboot3`（SB3 / jakarta），靠**手工 cherry-pick** 同步 |

**一句话评价**：认证内核已经成形、仓储层测试相对扎实；但**授权层存在功能性失效**，**加密工具层有一批真实缺陷**，**文档与代码已经脱节到会误导用户的程度**，且**长期没有任何 CI 兜底**（`1.5.0` 已由 ENG-1 补上）。当前瓶颈不是功能不足，而是「边界不清 + 工程欠账」。

---

## 2. 结论摘要

### 2.1 三个根因

**根因一：定位漂移——一个"有状态会话"库穿着 JWT 的外衣。**
每个请求都要查会话存储，JWT 只用来装一个 `credentials` 字符串。JWT 带来的全是成本：第二条过期时间线（`timeout` vs `jwt-timeout`，还发明了"取二者较大值"的补丁）、密钥管理坑（未配置就随机、重启全掉线）、`Bearer ` 前缀强制解析、签名开销、`credentials` 明文躺在 payload 里可被 base64 解出。**收益为零。** 这是当前概念债务的最大来源。

**根因二：架构在原地打转——三套并行 API + 一个静态全局桥。**
`AuthProvider` / `AuthUtil` / `TinySecurityFacade` 三套入口语义重复，靠 `AuthUtil.setFacade()` 这个静态变量互连。1.3.1 引入门面、1.4.0 统一语义又要删转发类——**三个版本都在重铺同一条管线，产品能力没有前进**。这是"改了很多但感觉没进步"的直接原因。

**根因三：差异化未被回答。**
语义上（`login` / `deleteByLoginId` / `max-concurrent-logins` / `getCredentialsByLoginId`）几乎处处对标 Sa-Token。因此"为什么用 tiny-security 而不是 Sa-Token / Spring Security / Shiro"目前**没有答案**。没有答案的库，功能只会越加越迷茫——因为每个需求都能加，但加完都不构成理由。

### 2.2 最该先做的 6 件事（按顺序，`1.5.0` 已全部完成）

| 顺序 | 事项 | ID | 为什么排这个位置 |
|---|---|---|---|
| 1 | ~~修 `AuthUtil.hasRole/hasPermission` 无注解接口恒 false 的回归（含测试同步改）~~ ✅ **`1.5.0` 已完成** | P0-1 / P0-2 | 用户最容易踩到的**功能性失效**，且改动小、价值立现 |
| 2 | ~~`random128` 与兜底 JWT 密钥改用 `SecureRandom`~~ ✅ **`1.5.0` 已完成** | P0-3 | **默认路径**下的弱密钥材料；文档还反向保证了安全性 |
| 3 | ~~`JsonUtil` 注册模块 + 容忍未知字段~~ ✅ **`1.5.0` 已完成** | P0-4 | 一行代码量级，同时解除「加字段=全员登出」的升级炸弹 |
| 4 | ~~修 `WebRequestUtils` 便捷重载默认允许 URL 传 token~~ ✅ **`1.5.0` 已完成** | P0-6 | 公开 API 的安全默认值与框架策略相反 |
| 5 | ~~修 `SM3Hash` null salt 碰撞 + 静默返回全 0 哈希~~ ✅ **`1.5.0` 已完成** | P0-7 | 真碰撞 + 静默失败，两者都违反自身规范 |
| 6 | ~~**加 CI**（`mvn -B verify` + JDK 17/21 矩阵）~~ ✅ **`1.5.0` 已完成** | ENG-1 | 性价比高于之后所有功能；没有它，前面 5 项修完还会退回去 |

> **`1.5.0` 定级修正**：原第 4 项 `BCrypt` 已移出本清单。复核确认它是**原样引入、在 `src/main/java` 中零引用**的第三方工具类，不在框架认证链路上；且原条目中"72 字节截断"与"work factor 取自存储值"两条实为 **bcrypt 算法规格，属误报**。详见 P0-5 与 P2-13 条目。

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
  - [`TinySecurityFacade.java:153-160`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/TinySecurityFacade.java#L153-L160)（`getRoleSet()` / `hasRole()` 读的就是这个空集；该类 `1.5.0` 移至 `provider` 包并降为包级私有）
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
- **修复记录（`1.5.0`）**：
  - `JsonUtil` 的 `ObjectMapper` 由裸 `new ObjectMapper()` 改为 `new ObjectMapper().findAndRegisterModules().disable(WRITE_DATES_AS_TIMESTAMPS)`：
    - `findAndRegisterModules()` 按 classpath 自动注册 JSR-310 / Jdk8 / ParameterNames 模块，`extraInfo` 里的 `LocalDateTime` 不再让登录 500；
    - 关闭 `WRITE_DATES_AS_TIMESTAMPS`，java.time 写成 ISO-8601 字符串（与 Spring Boot 自动配置的 ObjectMapper 一致），便于排查 Redis/JDBC 里的会话内容。
    - **选择 `findAndRegisterModules()` 而非显式 `new JavaTimeModule()`**：jsr310 只是 `spring-boot-starter-web` 的传递依赖，若被使用者 exclude，显式 new 会在类初始化阶段抛 `NoClassDefFoundError` 把整个框架一起拖垮；前者在缺少该模块时只是退回原行为。
  - `LoginSubject` 加 `@JsonIgnoreProperties(ignoreUnknown = true)`，新实例写入的会话在旧实例上仍可反序列化；并在类 javadoc 中写明「**只增字段，不改名不删除**」的演进约定。
  - 保留 `LoginSubject` 上的定向注解、**未**全局关闭 `FAIL_ON_UNKNOWN_PROPERTIES`：框架自有类型只有 `LoginSubject` 一个，其余读取目标都是 `Map`（本身已宽容），没必要为此放宽 `JsonUtil` 这个公开工具的整体严格性。
  - 新增回归测试 3 个：`JsonUtilTest` 的 java.time 值往返 + `extraInfo` 内 java.time 序列化；`LoginSubjectTest` 的未知字段容忍。
  - **反向验证**：撤掉这两处修复后重跑，3 个用例全部变红，报错正是本条描述的两个症状（`Java 8 date/time type java.time.LocalDateTime not supported by default`、`readValue` 返回 `null`）。
- **状态**：`DONE`（`1.5.0`）

#### P0-5 · `BCrypt` —— **定级修正：原样引入的 jBCrypt 0.4、零引用，降级合入 P2-13，本版本不修改**

- **类别**：第三方工具类 / 非框架链路
- **修正说明（`1.5.0` 复核）**：本条目原定级 `P0` 并列出 5 条"证据"。复核后确认**其中 2 条是误报**（把 bcrypt 算法规格当成了实现缺陷），定级也过高。更正如下。

**❌ 原文误报的两条 —— 实为 bcrypt 算法规格，任何实现都如此，不是缺陷：**

| 原文说法 | 实际情况 |
|---|---|
| "前 72 字节相同的两个密码**互相可验证通过**"（把 72 字节截断列为缺陷） | **算法固有**。`streamtoword` 按 `% data.length` 循环取字节，`key()` / `ekskey()` 各消费 P 数组 18 个字 = **72 字节**，password 第 73 字节起永不被读取。OpenBSD / jBCrypt / Spring Security 全部如此。**实测**：`checkpw("a"×72+"Y", hashpw("a"×72+"X", salt))` → `true` |
| "work factor 取自存储 hash，最高 2³⁰"（列为缺陷） | **bcrypt 要求 cost 必须编码在 hash 里**，否则无从校验；`crypt_raw` 自身已把 `log_rounds` 限制在 4~30。`$2a$30$` 的 CPU 开销只有在"存储的 hash 被外部输入控制"时才成立，属**条件性风险**，不是代码错误 |

**✅ 原文成立、已实测复现的部分（现集中记录在 P2-13）：**

- `char64` 差一错误 —— `index_64.length` 实测 = **128**，而边界写成 `> index_64.length`，故 `char64((char)128)` 会执行 `index_64[128]` → **`ArrayIndexOutOfBoundsException`**。**这是真 bug**。
- 畸形 / 截断 hash **抛异常而不是返回 `false`**（实测：`"$2a$"`、`"$2a$10$tooshort"` → `StringIndexOutOfBoundsException`；`"$2a$1a$…"` → `NumberFormatException`；`"not-a-hash"` → `IllegalArgumentException`），与 `checkpw` 自身 javadoc 的 `@return true/false` 契约冲突。
- `$2b$` / `$2y$` 一律 `IllegalArgumentException` → PHP `password_hash`、新版 OpenBSD 产物无法校验。
- `checkpw(null, hashOf("null"))` → **`true`**（`(password + "\000")` 把 `null` 拼成了字符串 `"null"`）。触发面很窄：仅当某用户口令字面量就是 `null` 时才会被空口令登入。

**🎯 影响面修正（这是降级的主要依据）：**

- 全 `src/main/java` grep `BCrypt`：**除该类自带的 `main()` 演示方法与 `BCryptTest` 外，没有任何生产代码引用它**；
- 因此它**不在认证链路上**，`checkpw` 的入参完全由使用者自己决定，框架不会向它传入任何数据；
- 影响面 = "主动调用 `BCrypt` 且传入脏数据 / 外来 hash 的使用者"，**不是全体用户**。原文"登录流程表现为 500"的措辞会让人误以为框架登录会 500，不准确。

- **结论**：**`WONTFIX`**（`1.5.0` 评估后决定不修改）。它就是一个原样引入的第三方工具类，上述问题与上游 jBCrypt 0.4 完全一致 —— "从官方复制的"这一点属实，但**上游原版本身就有这些写法问题**，两者并不矛盾。若将来要动，最小改动是 `char64` 的 `>` 改 `>=`（对合法 hash 零行为变化：合法字符码均在 46~122）。
- **状态**：`WONTFIX`

#### P0-6 · `WebRequestUtils` 的便捷重载默认**允许从 URL 读取 token**

- **类别**：安全 / 默认值不一致
- **证据**：[`WebRequestUtils.java:56-58`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L56-L58)、[`:67-69`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L67-L69)、[`:91-93`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L91-L93)、[`:103-105`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L103-L105)

  ```java
  getToken(tokenName)          → getToken(tokenName, true)          → 第三参 enableUrlToken = true  ❌
  getToken(request, tokenName) → getToken(request, tokenName, true) → enableUrlToken = true  ❌
  ```
- **影响**：1.3.3 刚把"URL 传 token"默认关闭（`AuthProvider` 走 [`resolveEnableUrlToken()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L480-L483) = false，**生产路径是安全的**），但**公开工具类的默认值仍是开**。用户直接调 `WebRequestUtils.getToken(request, "token")` 就把凭证重新暴露到访问日志 / Referer。同一份安全策略在两个入口给出相反默认值。
- **修复记录（`1.5.0`）**：`getToken(String)`、`getToken(String, boolean)`、`getToken(HttpServletRequest, String)`、`getToken(HttpServletRequest, String, boolean)` 四个便捷重载的 `enableUrlToken` 默认值由 `true` 改为 **`false`**，与 `AuthProperties.enableUrlToken = false` 的策略对齐；每个重载的 javadoc 均写明"1.5.0 起不再从 URL 读取 token"以及逃生通道。
  - **不受影响**：`AuthProvider` 一直显式调用四参重载（[`AuthProvider.java:75`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L75)、[`:91`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L91)），**生产鉴权路径行为完全不变**。
  - **破坏性**：依赖便捷重载从 `?token=xxx` 取值的外部代码会失效；确需从 URL 读取时改用四参重载并传 `true`。
  - 新增 `WebRequestUtilsTest` 共 7 个用例：header 读取、cookie 读取、**便捷重载不再读 URL**（覆盖 3 个重载）、显式开启后仍可读 URL、header 优先级、`enableCookie=false`、无来源返回 null。
  - **反向验证**：把四个默认值改回 `true` 后重跑，`shouldNotReadTokenFromUrlByDefault` 立即变红（`expected: <null> but was: <Bearer from-url>`）。
- **状态**：`DONE`（`1.5.0`）

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
- **修复记录（`1.5.0`）**：
  - **salt 归一化**：`SM3Encode(String, String)` 中 `salt == null` 时按 `""` 处理，杜绝了 `(source + salt)` 把 `null` 拼成字面量 `"null"` 造成的真碰撞；语义与 `SimpleHash` 的 JDK 分支保持一致。
  - **失败不再静默**：删除 `SM3Encode` 两处的 `catch (Exception)`，不再返回预分配的全 0 数组。同时移除了因此不再使用的 `Logger` 字段与 `slf4j` 导入。
    - 补充说明：该 `catch` 实为**死代码** —— `SM3Digest.update/doFinal` 均不抛受检异常，且 `source = null` 也不会触发异常（字符串拼接容忍 `null`）。因此这处改动是**消除隐患**而非修复现有故障，没有可直接构造的失败面；成功路径由既有的国密标准向量用例（`SM3("abc")`）守住。
  - **未采纳本条原建议的"统一盐序为 `H(salt‖source)`"**：SM3 分支盐序**保持** `H(source‖salt)` 不变。理由是——调换盐序会改变**所有带盐 SM3 哈希**的值（不只是 `salt=null` 这条路径），从而让使用者已存储的全部 SM3 哈希失效，而盐序本身不带来任何安全性差异，**收益为零、代价是又一次静默的数据失效**。若将来确需对齐，应作为独立的、显式公告的破坏性变更处理。
  - **兼容性影响（务必注意）**：`salt = null` 的调用哈希值会变，**存量哈希将无法校验通过**。受影响的具体调用已在 CHANGELOG「行为变更」中逐一列出 —— 特别提醒 `new SimpleHash("SM3", source)` 这个两参构造，它内部传的正是 `null`。
  - 新增回归测试 4 个：`SM3HashTest` 的「`null` 与 `""` 等价」「不再与字面量 `"null"` 碰撞」「`setSalt(null)` 与默认一致」「三参构造一致」；`SimpleHashTest` 的「SM3 分支与 JDK 分支语义对齐」。
  - **反向验证**：撤掉归一化后重跑，上述 4 个用例全部变红，且报错信息本身即实证 —— `expected: <08594e14…> but was: <e5ba5dc3…>`：前者是空盐哈希，后者正是**字面量 `"null"` 盐**的哈希，说明修复前 `salt=null` 走的确实是 `"null"` 那条路，两者相等即碰撞。
- **状态**：`DONE`（`1.5.0`）

---

### 3.2 P1 —— 高

#### P1-1 · 自定义 `TinySecurityFacade` Bean 会让 `AuthUtil`（及 `AuthProvider.getSecurityContext()`）整体瘫痪

- **证据**：[`AuthAutoConfiguration.java:256-266`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/AuthAutoConfiguration.java#L256-L266) —— `AuthUtil.setFacade(facade)`（`:260`）是**唯一**赋值点，而该方法带 `@ConditionalOnMissingBean(TinySecurityFacade.class)`（`:257`）。（行号为修复前；该 Bean 方法已随本次修复删除。）
- **影响**：用户一旦自己声明 `TinySecurityFacade` Bean（Spring 用户的本能），框架 Bean 被跳过 → 静态门面永远为 null → `AuthUtil.getLoginId()` 抛 `IllegalStateException`，**并连带 `AuthProvider.getSecurityContext()` 一起坏掉**（见 P1-2）。
- **旁证**：测试里专门有 `shouldNotOverrideUserDefinedAuthProvider`，却**没有** `TinySecurityFacade` 的对应用例。
- **修复方向**：把静态门面注入改为 `SmartInitializingSingleton` / `BeanPostProcessor` 级别的兜底，或**直接去掉静态门面**（推荐，见 §5 决策 2）。
- **状态**：`DONE`（`1.5.0`）

##### P1-1 / P1-2 实施记录（`1.5.0`）

按 §5 决策 2 执行：**两套 API 面 + 零可变静态全局**。

| 类 | 改造前 | 改造后 |
|---|---|---|
| `AuthProvider` | token/会话门面；`getSecurityContext()` 反向调 `AuthUtil` | **唯一实例门面**：`extends TinySecurityFacade`，继承上下文与授权能力（`getSecurityContext` / `getLoginId*` / `getRoleSet` / `hasRole*` / `hasPermission*`）。新增 5 参构造注入 `SecurityContextRepository` + `AuthorizationInfoGet`；**3 参构造保留**（内部退化为 `new ThreadLocalSecurityContextRepository()` + 无 SPI），手工 `new` 的旧用法不受影响 |
| `TinySecurityFacade` | 公开类，被 `AuthUtil` 通过静态变量反向持有 | 降为 **`provider` 包内包级私有**的内部基类，仅由 `AuthProvider` 继承；不再是容器 Bean |
| `AuthUtil` | 静态外观 + `static volatile TinySecurityFacade facade` + `setFacade`/`getFacade` | 静态外观，**零可变静态状态**：每次调用走 `当前请求 → ServletContext → WebApplicationContext → getBean(AuthProvider)` |
| `AuthAutoConfiguration` | 在 `@ConditionalOnMissingBean(TinySecurityFacade.class)` 的 Bean 里调 `AuthUtil.setFacade(...)`，启动横幅也挂在该 Bean 上 | 删除该 Bean；`authProvider(...)` 改为注入 `SecurityContextRepository` 与 `@Autowired(required = false) AuthorizationInfoGet`，启动横幅与版本日志随之迁到这里 |

- **为什么选"从当前请求的容器解析"**：容器里放的是谁就用谁，因此用户自定义 `AuthProvider` / `SecurityContextRepository` / `AuthorizationInfoGet` 全部照常生效，且 `AuthUtil` 与容器之间不再存在任何可以失同步的中间状态。
- **方案前提已实锤**：该做法依赖「ServletContext 的 `ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE` 指向当前容器」。对 `ServletWebServerApplicationContext` 反查字节码确认它确实会 `servletContext.setAttribute(ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ...)`；`@SpringBootTest` 环境下同样成立（由 `TinySecurityAutoConfigurationTest` 断言）。
- **解析方式的两处加固**：
  1. 用 `WebApplicationContextUtils.findWebApplicationContext(...)` 而非 `getWebApplicationContext(...)`：前者在 ROOT 属性取不到容器时会**继续扫描 ServletContext 的全部属性**，从而兼容「Bean 注册在 `DispatcherServlet` 子容器里」的经典 Spring MVC 部署；在 Spring Boot（ROOT 属性即应用容器）下两者行为完全一致，无额外开销。
  2. 单独捕获 `NoUniqueBeanDefinitionException`：它是 `NoSuchBeanDefinitionException` 的**子类**，若只捕获后者，容器里存在两个 `AuthProvider` 候选 Bean 时会被误报成「一个都没有」，把排查方向带反。已加回归用例 `shouldReportMultipleCandidatesInsteadOfMissingBean`，并做了反向验证（去掉该分支后该用例立即变红）。
- **残留边界（已知、可接受）**：若同时存在 `ContextLoaderListener` 的根容器与 `DispatcherServlet` 子容器，且 `AuthProvider` 只注册在**子容器**，那解析到的是根容器，`getBean` 会失败。这是「仅凭 ServletContext 定位容器」的固有限制，且与框架定位（Spring Boot starter）无关 —— Boot 下只有一个应用容器。
- **对外行为不变**：`AuthUtil` 的方法签名与语义完全不变；未登录/会话失效仍统一抛 `UnAuthorizedException`；无注解接口上的 `hasRole`/`hasPermission` 仍按需懒加载（P0-1）。
- **已知限制（取舍）**：`AuthUtil` 只适用于持有当前请求的线程。非 Web 线程（`@Async`、MQ 消费线程）取不到请求，抛 `UnAuthorizedException` —— 与 `1.5.0` 之前一致；这类场景请直接注入 `AuthProvider`。该限制已判定为**使用方式问题而非框架缺陷**（见 P1-3 的定级修正），框架不做自动传播。
- **破坏性变更**：`TinySecurityFacade` 不再公开（包级私有且移到 `provider` 包）；`AuthUtil.setFacade` / `AuthUtil.getFacade` 删除；容器里不再有 `tinySecurityFacade` Bean。
- **反向验证**（两处，均确认用例真能抓住缺陷）：
  1. 把 `AuthUtil` 的「每请求解析」退化成「首次解析后缓存进静态字段」（即 P1-1 的失败形态）→ `AuthUtilTest` 7 个用例中 **5 个立即变红**，头号用例报错正是症结：`expected: <second-user> but was: <first-user>`。
  2. 把 P1-2 的旧实现（`AuthProvider.getSecurityContext()` 改走 `AuthUtil`）加回去 → `AuthProviderSecurityContextTest` 两个用例全部变红，报错为 `IllegalStateException: No WebApplicationContext found for the current request`，即"脱离容器就废"。
- **测试同步**：`AuthUtilTest` 新增「跟随当前请求容器而非任何静态状态」「无 `WebApplicationContext`」「容器内无 `AuthProvider` Bean」三条，并接收从 `TinySecurityFacadeTest` 迁来的「经 `AuthUtil` 的懒加载完整路径」「`get*` 转发」两条；`AuthProviderSecurityContextTest` 不再需要任何静态注册；`TinySecurityFacadeTest` 随被测类移入 `provider` 包；新增测试辅助 `AuthTestSupport` 复刻真实 Web 装配（ServletContext + 容器 + `RequestContextHolder`）。

#### P1-2 · `AuthProvider` 反向依赖静态 `AuthUtil`，靠测试手工注册才跑得通

- **证据**：[`AuthProvider.java:392-399`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L392-L399)（`getSecurityContext()` 调 `AuthUtil.getSecurityContext()`，即一个 Spring Bean 依赖"另一个 Bean 在构造时顺手赋值的静态变量"）。（行号为修复前；该重写方法已删除，能力改由 `TinySecurityFacade.getSecurityContext()` 经**注入的** `SecurityContextRepository` 提供。）
- **旁证**：[`AuthProviderSecurityContextTest`](../tiny-security-core/src/test/java/org/tinycloud/security/provider/AuthProviderSecurityContextTest.java) 必须显式 `AuthUtil.setFacade(...)` 才能让被测方法工作。（修复后该文件已不需要任何静态注册。）
- **影响**：手工 `new AuthProvider(...)`（README §2.5.2 风格）、单测、非 Web 线程都会拿不到上下文。
- **修复方向**：`AuthProvider` 直接注入 `SecurityContextRepository`。
- **状态**：`DONE`（`1.5.0`，与 P1-1 同批；实施细节与反向验证见上方记录）

#### P1-3 · 异步线程拿不到安全上下文 —— **定级修正：判定为使用方式问题，不修改**

- **证据**：[`ThreadLocalSecurityContextRepository.java:17`](../tiny-security-core/src/main/java/org/tinycloud/security/context/ThreadLocalSecurityContextRepository.java#L17)（纯 ThreadLocal）+ [`AuthenticationInterceptor.java:50-55`](../tiny-security-core/src/main/java/org/tinycloud/security/interceptor/AuthenticationInterceptor.java#L50-L55)（1.3.3 加的**入口兜底清理**只解决了"上一请求残留"）
- **现象**：`Callable` / `DeferredResult` / `@Async` / MQ 消费线程里调用 `AuthUtil.*` 会抛 `UnAuthorizedException`（与 `1.5.0` 之前一致）。
- **为什么不修（决策，`1.5.0`）**：线程绑定的上下文在切线程后失效，与 `RequestContextHolder` / `SecurityContextHolder` / `TransactionSynchronizationManager` 完全同构 —— **在异步线程里取请求作用域的状态本身就是误用**，应由使用者规避（改为注入 `AuthProvider`），框架不承担这个责任。
  - **Spring 的同款先例**：`SecurityContextHolder` 同样是 ThreadLocal，Spring Security 的答案不是"自动传播"，而是提供一个**可选**的 `DelegatingSecurityContextAsyncTaskExecutor`，由使用者显式装配。
  - **实测确认框架自身没有这个坑**：框架自有的两条后台线程都只做过期清理、不需要身份 —— [`JdbcSessionRepository.java:254`](../tiny-security-core/src/main/java/org/tinycloud/security/session/JdbcSessionRepository.java#L254) 只跑 `DELETE ... WHERE credentials_expire_time < ?`，[`LocalTimeCache.java:228`](../tiny-security-core/src/main/java/org/tinycloud/security/session/timedcache/LocalTimeCache.java#L228) 只跑 `refreshDataMap()`。即"需要身份的工作"从不被框架丢到别的线程，责任边界清晰。
- **原"修复方向"的评估结论（不采纳，记录以备将来）**：`SecurityContextPropagator` / `TaskDecorator` 只对 `@Async` 便宜（已反查字节码确认 Boot 消费 `ObjectProvider<TaskDecorator>`：`TaskExecutorConfigurations$ThreadPoolTaskExecutorBuilderConfiguration.threadPoolTaskExecutorBuilder(...)`，故声明一个 `TaskDecorator` Bean 即自动接到 `applicationTaskExecutor`，用户零配置），`Callable`/`DeferredResult` 需另装 `AsyncTaskExecutor` 并先实测，而 **MQ 消费根本传播不了**（`TaskDecorator.decorate()` 在提交方线程执行，MQ 消费者没有提交方，只能让消息携带身份显式重建）。三者难度差一个数量级，并列为一条待办本身就不成立。
  - 另有一处技术遗漏：只传播 `SecurityContext` **不够** —— `AuthUtil` 的第一步是读 `RequestContextHolder`（[`WebRequestUtils.java:29-35`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java#L29-L35)），必须连 `RequestAttributes` 一并传播，或改成"上下文可从 request 取得"。
  - 若将来仍要做，应作为**可选**能力（提供装饰器 Bean、不自动生效），且需先拍板"传播 `RequestAttributes` 还是传播已解析的 `AuthProvider` 引用"（前者把 request 引用带出请求生命周期，后者需给 `AuthUtil` 开一个线程绑定的覆盖入口）。
- **配套**：用户可见文档需补这条边界，见 §3.5 `DOC-14`。
- **状态**：`WONTFIX`

#### P1-4 · 注解只认「方法本身 + 方法直接声明类」，父类/接口上的注解被忽略 → 静默失去保护

- **证据**：[`AnnotationUtils.java:45-65`](../tiny-security-core/src/main/java/org/tinycloud/security/annotation/AnnotationUtils.java#L45-L65)（`method.getAnnotation(...)` + `method.getDeclaringClass().getAnnotation(...)`）
- **影响**：注解查不到时，[`AuthorizationInterceptor.java:86`](../tiny-security-core/src/main/java/org/tinycloud/security/interceptor/AuthorizationInterceptor.java#L86) 与 [`DefaultAuthorizationManager.java:48`](../tiny-security-core/src/main/java/org/tinycloud/security/authorization/DefaultAuthorizationManager.java#L48) 都会把接口判定成「无注解接口」→ **直接放行**。这是安全方向的失败（fail-open）：本该拦住的请求被静默放过，且没有任何报错或日志。
- **触发条件（`1.5.0` 实施时逐条实测修正，原文描述不准）**：拦截器取的是 [`((HandlerMethod) handler).getMethod()`](../tiny-security-core/src/main/java/org/tinycloud/security/interceptor/AuthorizationInterceptor.java#L73)，因此「父类标了注解、子类只继承不重写」这一场景**不会**漏 —— 此时反射拿到的 `Method` 其 `getDeclaringClass()` 就是父类，`getAnnotation` 直接读得到（已用用例 `shouldFindAnnotationOnDeclaringClass` 钉住）。真正 fail-open 的是下面三种：

  | # | 写法 | 为什么漏 |
  |---|---|---|
  | 1 | 子类**重写**了父类带注解的方法、自己没重新标注 | 声明类变成子类，而**方法注解不可继承**（与 `@Inherited` 无关） |
  | 2 | 注解标在**接口方法**上、实现类方法未标注 | 方法注解同样不随实现继承 |
  | 3 | 用**组合注解**（自定义注解上标 `@RequiresPermissions`） | `getAnnotation` **不解析元注解** |
- **修复方案（`1.5.0` 已实施）**：三处查找（`findRequiresPermissions` / `findRequiresRoles` / `findIgnore`）统一改用 `AnnotatedElementUtils.findMergedAnnotation`，先查方法（沿父类/接口的同名方法上溯），再查方法声明类（沿其父类/接口上溯）。该方法同时解析元注解，一次覆盖上表三种写法。
- **状态**：`DONE`（`1.5.0`，实施记录与反向验证见下方）

##### P1-4 实施记录（`1.5.0`）

| 项 | 内容 |
|---|---|
| 改动 | [`AnnotationUtils`](../tiny-security-core/src/main/java/org/tinycloud/security/annotation/AnnotationUtils.java) 三个查找方法（`findRequiresPermissions` / `findRequiresRoles` / `findIgnore`）由 `getAnnotation` 改为 `AnnotatedElementUtils.findMergedAnnotation`，查找顺序为「方法 → 方法声明类」，各自内部再沿父类/接口上溯 |
| 破坏性变更 | 无（对外方法签名一字未变，只是查找范围变宽） |
| 行为变更 | 原先漏掉的三种写法现在会生效；副作用是**对 `@Ignore` 也一并生效**（父类/接口上的 `@Ignore` 在重写/实现后不再被忽略）。因 `@Ignore` 是用户显式写的框架自有注解，按「尊重用户意图」处理 |
| 验证 | JDK 17 与 21 均 `mvn -B clean verify` 成功（core 199 / starter 16） |

- **先证缺陷、再动代码**：新增 [`AnnotationUtilsTest`](../tiny-security-core/src/test/java/org/tinycloud/security/annotation/AnnotationUtilsTest.java)（9 例），改动前先跑一遍 —— 恰好 5 例变红（3 种 fail-open 写法 × 权限/角色/`@Ignore`），确认缺陷真实存在而非推测；修复后 9/9 全绿。此前 `AnnotationUtils` 属 TST-2 所列的零测试类。
- **链路级证明（关键）**：`AnnotationUtils` 只是工具类，真正要证的是**授权决策**从「放行」变「拦截」。在 [`DefaultAuthorizationManagerTest`](../tiny-security-core/src/test/java/org/tinycloud/security/authorization/DefaultAuthorizationManagerTest.java) 补 2 例，让重写父类方法 / 实现接口方法的场景真的走一遍 `authorize(...)`，断言 `decision.isGranted() == false`。
- **反向验证**：只把 `findRequiresPermissions` 一处退回 `getAnnotation`（保留角色与 `@Ignore` 的修复），`AnnotationUtilsTest` 3 例 + `DefaultAuthorizationManagerTest` 2 例变红，其中链路级报错正是 `expected: <false> but was: <true>` —— 即授权决策退化成**放行**，fail-open 在决策层被实锤。变异点（2 处）与还原（6 处 `findMergedAnnotation`）均已核对。
- **残留边界（已知、未修）**：若注解标在**运行时子类**上、而方法声明在父类（`UserController extends BaseCrudController`，注解写在 `UserController` 上、方法继承自基类），查找用的是 `method.getDeclaringClass()`，仍会漏。Spring 自己在 `AbstractFallbackTransactionAttributeSource` 里是用 `ClassUtils.getUserClass(targetClass)` 解决的。补齐需要把处理器类型（`HandlerMethod.getBeanType()`）穿到 `AnnotationUtils` 与 `AuthorizationManager.authorize(...)`，属对外 API 变更，留待阶段 2 做「注解继承」时一并处理。

#### P1-5 · Cookie 模式的两个真实缺陷

- **证据**：
  - [`CookieUtil.removeCookie()`](../tiny-security-core/src/main/java/org/tinycloud/security/util/CookieUtil.java)（原先删除 Cookie 只带 `path`/`maxAge=0`/`HttpOnly`，**不带 `SameSite` 也不带 `Secure`**）
  - [`AuthProvider.logout(HttpServletRequest)`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java)（原先内部用的是 `WebRequestUtils.getResponse()`，**不是**由传入的 `request` 推导）
- **影响**：
  1. `SameSite=None` 时浏览器要求删除指令同样带 `SameSite=None; Secure`，否则**删除被忽略** → "登出后仍是登录态"；
  2. 非 Web 线程 / 显式传 `request` 的场景下 Cookie **不会被清理**（静默）。
- **旁证**：`AuthProviderCookieTest` 只断言了 `maxAge == 0`，未断言属性 —— 这正是缺陷能存活至今的原因。
- **状态**：`DONE`（`1.5.0`）

##### P1-5 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 缺陷 A 修复 | `removeCookie` 新增五参重载（`path`/`secure`/`sameSite`），补齐 `setSecure(secure)` 与 `SameSite` 属性；`AuthProvider` 登出时传入 `resolveCookieSecure()`/`resolveCookieSameSite()`，与写入时**同源取值**。原两参/三参重载保留（委托新重载，属性取默认值），公开 API 未破坏 |
| 为什么属性必须逐字一致 | 删除 Cookie 的本质是"写回同名 Cookie 并令 `maxAge=0`"，浏览器仅在 `path`/`domain` 与**安全属性**均匹配时才视为同一条并执行删除。`SameSite=None` 的 Cookie 规范要求必须伴随 `Secure`，删除指令缺失这两个属性会被**直接忽略** —— 用户点了登出、Cookie 还在 |
| 缺陷 B 修复 | 新增 [`WebRequestUtils.getResponse(HttpServletRequest)`](../tiny-security-core/src/main/java/org/tinycloud/security/web/WebRequestUtils.java)：先核对线程绑定的请求是否**就是**传入的那一个，是则返回其响应，否则返回 `null`。`logout(request)` 改用它 |
| 为什么不是"直接由 request 推导 response" | **Servlet API 无法从请求反查响应** —— 响应只能来自线程绑定（`RequestContextHolder`），请求对象上没有指向响应的入口。因此能做到的正确语义是：**校验同一性，不一致时宁可不清理，也不写错对象**。这样既消除了"把清理写到别的请求响应上"（静默污染另一个响应），又保留了正常 Web 请求下的既有行为（二者本就是同一实例） |
| 先证缺陷 | 新增 4 条用例。缺陷 A 两条在改动前变红：`shouldClearCookieWithSameSecurityAttributesAsWritten:178`（`Secure` 不一致：`expected: <true> but was: <false>`）与 `shouldClearCookieWithDefaultSecurityAttributes:209`（`SameSite` 丢失：`expected: <Lax> but was: <null>`） |
| 反向验证 | ① 把 `removeCookie` 的 `setSecure(secure)` 变异为 `setSecure(false)` → `shouldClearCookieWithSameSecurityAttributesAsWritten:178` 变红；② 把 `getResponse(request)` 的同一性校验变异为恒假 → `logoutWithRequestShouldNotWriteToUnrelatedResponse:243` 变红，报错为 `expected: <null> but was: <Cookie@...>`（清理写到了无关响应上）。两处变异均先断言锚点命中数再执行 |
| 排查记录 | 缺陷 B 的第一版用例**设计有误**：它把传入的 request 也绑进了线程上下文，于是 `getResponse()` 恰好拿到同一个 response，用例在修复前就通过 —— **测不出缺陷**。改为"线程绑定无关 request"后才真实复现。教训同 P1-12：**用例的替身/环境必须保真到会出问题的那一层** |
| 测试同步 | `AuthProviderCookieTest` 9 例 → 14 例：删除指令的 `Secure`/`SameSite`/`path`/`HttpOnly` 一致性、默认 `Lax` 场景、`logout(request)` 不得写到无关响应、同请求下正常清理 |

#### P1-6 · 内核不做绝对过期校验，把"会话是否过期"外包给仓储实现

- **证据**：[`DefaultAuthenticationManager.java:53-65`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L53-L65)（只判断"剩余 TTL 是否 ≤ timeout×20%"，**从不判断是否已过期**）
- **影响**：四个内置仓储确实过滤了过期，但 README 明确鼓励用户自定义仓储 —— 一旦漏了这层过滤，**过期会话会被无限续期**（走刷新分支 `setLoginExpireTime(now + timeout)` 把它复活）。安全框架不该把核心判定外包给插件。
- **修复方向**：内核加一次 `expireTime <= now → 401`。
- **状态**：`DONE`（`1.5.0`）

##### P1-6 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 改动 | [`DefaultAuthenticationManager.authenticate()`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L58-L67) 在续期判断**之前**增加绝对过期校验：`expireTime == null \|\| expireTime <= currentTime` → `UnAuthorizedException` |
| 位置理由 | 必须放在续期分支**之前**。续期条件是 `expireTime - currentTime <= millsCritical`，对已过期会话左侧恒为负数、条件**必然成立** —— 顺序颠倒就还是复活 |
| 顺带加固 | `long expireTime` 改为 `Long` 并先判 `null`：自定义仓储返回不完整主体时，原来是拆箱 NPE(500)，现在按"已失效"返回 401（与"未登录/会话失效"语义一致） |
| 为什么"仓储已过滤还要再判一次" | 这是本项被质疑最多的一点，结论是**必须判**：① [`SessionRepository.getSubject`](../tiny-security-core/src/main/java/org/tinycloud/security/session/SessionRepository.java#L33-L39) 的契约只写了 `@return 登录主体`，**从未承诺**过期时返回 `null`（对比同一接口的 `getCredentialsByLoginId`，那里明确写了"有效（未过期）""不返回 null"）—— 内核消费的是 SPI，不能依赖一条没有写下来的义务；② 即便用**内置**仓储，「存储层 TTL」与 `subject.loginExpireTime` 也是两个**互相独立的量**：`save(subject, timeoutSeconds, max)` 的这两个参数由调用方分别给出，single 仓储不校验二者一致。已用内置 `SingleSessionRepository` 实测出"存储层仍有效、`loginExpireTime` 已过期 60 秒"的会话被 `getSubject` 正常返回、`checkByCredentials` 也返回 true |
| 测试 | `DefaultAuthenticationManagerTest` 由 4 个增至 7 个用例：`shouldRejectExpiredSubjectInsteadOfRefreshingIt`（过期 → 401 且不得改写过期时间）、`shouldAcceptNeverExpiringSubjectWithoutRefresh`（永不过期护栏）、`shouldRejectStoreValidButExpiredSubjectOnBuiltInSingleRepository`（**用内置 single 仓储**复现上面第 ② 点，证明该分支在生产路径上真的够得着，而不只是"自定义仓储才可能"） |
| 反向验证 | 把校验改成 `if (false)`：假仓储与内置仓储两条用例**同时**变红，均报 `Expected UnAuthorizedException to be thrown, but nothing was thrown`（`:134` / `:206`）—— 即**过期会话被放行**。去掉校验后的实测输出为"放行 ✗，续期后 expireTime 距现在 1800 秒"，复活行为被直接观察到 |
| 边界 | 本项只解决"已过期不得使用"；**会话在存储侧的清理**仍由各仓储负责（缓存过期、JDBC 的 `DELETE ... < now`），内核不做存储层清理 |

#### P1-7 · 并发登录上限是 check-then-act，且四个仓储强度不同

- **证据**：
  - [`RedisSessionRepository.java:224-254`](../tiny-security-core/src/main/java/org/tinycloud/security/session/RedisSessionRepository.java#L224-L254)（有"先 count 检查 + push 后再查 size 检查"**两道**）
  - [`JdbcSessionRepository.java:230-237`](../tiny-security-core/src/main/java/org/tinycloud/security/session/JdbcSessionRepository.java#L230-L237)、[`SingleSessionRepository.java:230-237`](../tiny-security-core/src/main/java/org/tinycloud/security/session/SingleSessionRepository.java#L230-L237)、[`CaffeineSessionRepository.java:263-270`](../tiny-security-core/src/main/java/org/tinycloud/security/session/CaffeineSessionRepository.java#L263-L270)（**只有第一道**）
- **影响**：并发登录突发时 JDBC/内存版可突破上限；Redis 版存在"两个并发请求各自 push 后都超额、于是都自我移除 → 明明有空位却双双失败"的边缘情形。测试全是串行的。
- **修复方向**：Redis 用 Lua 保证原子；JDBC 用唯一约束/乐观锁；内存版加锁。四个仓储行为必须一致。
- **现状核实（`1.5.0`）**：全仓库**不存在任何** Lua / `RedisScript` / `EVAL` / `MULTI-WATCH`，Redis 侧只有 `setIfAbsent` / `set` / `expire` / `rightPush` / `remove` / `size` 等单命令原语 —— 即上面两道闸门**至今仍是非原子的**，本项尚未动工。两种竞态后果：① Redis 在 `max=1` 且两个并发登录同时看到 `0 < 1` 时，双方各自 `rightPush` 后都发现超额、都摘掉自己、**双双失败**，而实际还剩一个空位；② JDBC / Single / Caffeine 只有第一道闸门，两个并发请求会**直接突破上限**（静默超额）。
- **排期调整与撤回（`1.5.0`）**：本项曾计划从 §4.3 第 4 行下移到第 8 行（与 TCK 同批），理由是"四个仓储一致"应由 TCK 判定。随后决定**就地完成**，因为真实 Redis 实测（见下）表明它的严重程度远超"一致性"范畴 —— 配了并发上限的账号在突发登录下**一个也登不进来**。TCK 的收敛判定仍然有效，但不应作为推迟一个"登录不可用"缺陷的理由。
- **状态**：`DONE（3/4）`（`1.5.0`）—— Redis / Single / Caffeine 已做到**可证明的原子**；Jdbc 是**残余项**，见下

##### P1-7 实施记录（1.5.0）

**先取证（真实环境）**：修复前用同一探针压测，`maxConcurrentLogins = 1`、4 个并发登录，**3/3 轮都是 0 成功、4 个全被拒、在线列表空** —— 这不是"上限被绕过"，而是"谁都登不进来"。JDBC（H2）同样实测：`max = 3`、16 个并发线程 **16/16 全部成功**（3/3 轮），上限完全失效。

| 仓储 | 修复方式 | 原子性依据 |
|---|---|---|
| `redis` | 新增 Lua 脚本 `ADD_TO_ONLINE_LIST_SCRIPT`：`LLEN >= max ? return 0 : RPUSH + EXPIRE` 一次执行 | Redis 单线程执行脚本，天然原子。脚本**只操作 KEYS[1] 一个键** —— Redis Cluster 要求脚本内所有键同属一个 slot，而"凭证 key"与"在线列表 key"天然不同 slot，故失效凭证清理仍留在 Java 侧 |
| `single` | `addToOnlineListIfLimitNotExceeded()`：把 `countValidOnlineSessions()` 挪进**已有的** `onlineLock` 内，与 `add` 同锁 | `synchronized` 互斥（可重入，count 内部原也有同锁） |
| `caffeine` | 同上，同样复用已有的 `onlineLock` | 同上 |

| 项 | 内容 |
|---|---|
| 关键顺序 | 三处都改成**先写会话、再原子占名额**。反过来（先占名额）会踩到一个更隐蔽的竞态：并发的清理逻辑会因为"凭证 key 还没写入"而把刚入列的凭证**误判为失效并移除**，结果是会话存在却不在列表里，上限被静默绕过 |
| 失败必须回滚 | 占名额失败（含脚本返回 0、以及占名额这一步自身抛异常）都必须**删掉刚写入的会话**再抛 `ConcurrentLoginOverLimitException`；否则留下一个不在在线列表里、却可以正常使用的会话。<br>**顺带修掉一个此前未被发现的同类缺陷**：修复前 Redis 在超限路径上是"push → 发现超额 → 摘掉自己 → 抛异常"，**始终没有删除会话 key**，于是被"拒绝"的那次登录反而留下一个可用且未被计数的会话 —— 即超限分支本身就在**绕过上限**，安全性上比"登不进来"更糟 |
| 新增的部署前提 | Redis 路径现在依赖 **`EVAL`（Lua 脚本）**。标准 Redis / ElastiCache 均支持；但**不支持 `EVAL` 的代理或兼容服务（如 Twemproxy）会让登录直接失败**（失败是响亮的：`save` 返回 false，不静默）。已写入 CHANGELOG 升级检查清单，并给出替代方案（切 `single` / `caffeine`） |
| 触发条件（严重性定位） | 本项是**预防性质**：`maxConcurrentLogins` 默认值就是 `0`（不限制，见 `AuthProperties.java:45`），整条判定路径默认根本不执行；即便配了上限，也需要**同一账号在几毫秒内**发生两次登录（客户端双击、超时重试、移动端多个 401 并行触发重新登录）。因此它不是"线上随时会炸"的缺陷，而是"一旦配了上限就会踩到"的缺陷 —— 这也是本次不值得为 JDBC 残余付出破坏性 DDL 的理由之一 |
| 删除的两步写法 | Redis 原"push 后再查 size、超了自己摘掉自己"的第二道闸门**整段删除** —— 它既是"双双失败"的成因，在原子脚本下也不再需要 |
| Redis 保留第一道闸门 | `checkMaxLoginLimit()` 仍作为快速失败路径保留（命中时连会话都不写），真正的判定移到脚本内 |
| 返回值 `null` 的处理 | 脚本异常地返回 `null` 时按"未入列"处理（拒绝登录）—— 安全方向，绝不放过一个未被计数的会话 |
| 并发测试 | `SingleSessionRepositoryTest` / `CaffeineSessionRepositoryTest` 各新增 `concurrentLoginsShouldNotExceedLimit`：16 线程卡同一栅栏同时登录、`max=3`，断言**恰好** 3 个成功、13 个被明确拒绝、在线数=3。这是本仓库**第一批并发用例**（此前全是串行） |
| Redis 契约测试 | `RedisSessionRepositoryTest` 新增 2 个：`saveShouldJudgeConcurrentLimitAtomicallyInScript`（断言上限值随脚本下传，且 `rightPush` / `size` **从不**被调用）、`saveShouldRollbackSessionWhenScriptRejectsOverLimit`（脚本返回 0 时必须回滚会话） |
| 反向验证 | 去掉内存版原子守卫（`if (false)`）后并发用例**如实变红**：Single `concurrentLoginsShouldNotExceedLimit:278 expected: <3> but was: <4>`、Caffeine `:241 expected: <3> but was: <13>` —— 即静默超额 |
| **Jdbc 残余（未修）** | JDBC 的"先 COUNT 再 INSERT"要真正原子，必须让两步处于同一临界区，而 `JdbcSessionRepository` 只有裸 `JdbcTemplate`（每条语句自动提交），没有事务管理器。三个**不需要改表结构**的候选方案已逐个实测否决：<br>① **单条条件 INSERT**（`INSERT ... SELECT ... WHERE (SELECT COUNT(1) ...) < ?`）：实测 **16/14 行 ≠ 3**，子查询不加锁、各语句各自读快照，**不原子**；<br>② **事务 + `SELECT COUNT(1) ... FOR UPDATE`**：H2 直接报 `FOR UPDATE is not allowed in DISTINCT or grouped select`，聚合与 `FOR UPDATE` 不能共存，**跑不通**；<br>③ **事务 + `SELECT credentials ... FOR UPDATE`**（不加聚合）：只能锁住**已存在**的会话行；账号会话数为 0 时无行可锁，而 H2 / PostgreSQL 无间隙锁 → 最坏情形（空列表并发登录）依然突破上限。<br>**结论**：需要**改表结构**才能真正闭合 —— 例如按 `(login_id, slot)` 建唯一索引、或加一张"每账号一行"的锁表配合事务。两者对既有部署都是**破坏性变更**（需 DDL 迁移），且要引入事务管理，故**未擅自实施**，留待决策。当前 JDBC 仍是 best-effort：串行登录守上限，并发下会突破 |
| **为什么"上事务"不是解法** | 曾被考虑的"引入事务管理"方向经核实应当**否决**，理由不是复杂而是**修不好**：① `JdbcSessionRepository(JdbcTemplate, String tableName)` 是**公共构造器**，starter 在 `AuthAutoConfiguration:137` 直接 `new`，加事务管理器就要改这个签名（或手写 `setAutoCommit(false)` 的 `ConnectionCallback`），属公共 API 变更；② 更关键的是上面第 ②③ 项实测 —— 加锁读在 H2 上要么语法不通、要么锁不住"账号当前 0 个会话"这个最坏情形，只有在 MySQL 的 REPEATABLE READ 下**隐式依赖间隙锁**才勉强成立，是一条不可见且不可移植的依赖；③ 还会在登录热路径上把连接池连接持有到临界区结束。补充：**这不是"要不要加依赖"的问题** —— `spring-tx:6.1.15` 早已在类路径上（见 `dependency:tree`），纯粹是 API 与语义代价。**真正可行的是不要事务的槽位唯一索引方案**（见 §4.3 第 13 行） |
| 兜底建议 | 需要**硬性**并发上限的用户，当前零改动即可满足：把 `tiny-security.store-type` 切到 `redis` / `single` / `caffeine` —— 三者已做到可证明的原子（其中 `single` 还是默认值）。只有在必须用 `jdbc` 存储且必须硬限并发时，才值得付出槽位 DDL 的代价 |

#### P1-8 · `timeout <= 0` 在四个仓储里有四种语义；`AuthProperties` 无任何校验

- **证据**：[`AuthProperties.java`](../tiny-security-core/src/main/java/org/tinycloud/security/config/AuthProperties.java)（无 `@Validated` / `@Min`）

  | 仓储 | `timeout = -1` 的行为（**修复前**，均为真实环境实测结论） |
  |---|---|
  | Single | `NEVER_EXPIRE`，永不过期 —— **本来就对** |
  | Caffeine | 铸造出的 `loginExpireTime` 是过去时间 → `nanosUntilExpire` 返回 0 → **立即驱逐** |
  | Redis | **两条写路径行为不同**：`save` 的 SET NX 路径容忍 `-1` 并落成无 TTL（正常）；`refreshByCredentials` 的 SETEX 路径报 `ERR invalid expire time in setex` → 异常被 `catch` 吞掉 → **续期静默失败** |
  | Jdbc | 写入过去的 `credentials_expire_time` → **立即过期** |

  > **勘误**：本条目最初把 Redis 写成"`expire(key, -1)` → 异常 → 登录失败"。经真实 Redis 实测，**该结论是错的** —— 登录写入路径（SET NX）并不报错。真正出问题的是续期路径（SETEX）。原始判断错在把"原始 `SET ... EX -1` 会被拒"直接外推到了框架实际调用的 Spring Data 重载上。
- **影响**：配置错了（`timeout: -1` 是很多同类框架表示"永不过期"的写法）不会有任何提示，行为还因仓储而异。**真正非法的其实是 `0` / `-2`**：实测 Redis 会抛 `RedisSystemException`（`ERR invalid expire time`）导致登录失败，而 Single / Caffeine / Jdbc 会"静默地发出一个立即失效的会话"。
- **修复方向**：统一语义 + 启动期校验。
- **状态**：`DONE`（`1.5.0`）—— **最终方案：`timeout` 只允许正数，任何非正值装配期直接拒绝**（曾短暂实现过"`-1` = 永不过期"，已推翻，理由见实施记录）

##### P1-8 实施记录（1.5.0）

**语义决策（含一次自我推翻）**：`timeout` 只有一种含义 —— **正数秒数**；`null`（未配置）沿用 1800 秒默认值；**`0` 与一切负数一律在装配阶段拒绝**。

> **推翻记录**：本项最初采纳的是"折中方案"——把 `-1` 定义为"永不过期"、其余非正值拒绝，并为此引入了 `NEVER_EXPIRE_TIMEOUT = -1` / `NEVER_EXPIRE_TIME = Long.MAX_VALUE` 两个常量与四个仓储的配套分支。该方案**已整体取消**，原因有三：
> ① **收益存疑**："永不过期"对安全框架是反模式（凭证一旦泄露即永无失效），把它作为一个受支持的配置去精细实现，投入产出不划算；
> ② **复杂度真实**：它要求保证"存储层 TTL"与 `loginExpireTime` 两套过期口径处处一致，而公开方法 `AuthProvider.refreshByCredentials(credentials, subject)` 只维护前者、不维护后者 —— 两套口径一旦分叉，内核的绝对过期校验会把会话判成 401（旧的滑动续期曾把这个缝"顺手补上"，所以问题一直被掩盖）；
> ③ **留下了地雷**：`DefaultAuthenticationManager` 的续期会算 `currentTime + timeout * 1000L`，在 `timeout = -1` 下得到的是**过去时间**。它当时不可达，纯粹是因为"绝对过期校验"恰好排在续期判断之前——两个改动**碰巧叠对了**，而非设计保证。任何人调整那段判断的顺序，都会静默造成全量登出。
> 取消 `-1` 后，①②③ 同时消失：仓储侧不再有任何"永不过期"分支，`-1` 也永远不会流到内核。

| 项 | 内容 |
|---|---|
| 装配期校验 | [`AuthProvider` 构造器](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L108-L116)：`Assert.isTrue(timeout == null \|\| timeout > 0, ...)`。**不能用 `@Validated` + `@Min`**：类路径上没有任何 JSR-380 校验器（已实测 `dependency:tree`），注解会**静默空转**，是个假修复 |
| 铸造点 | [`AuthProvider.login()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L209-L213)：`currentTime + timeout * 1000L`，恢复为单一表达式（原先的"哨兵三元"已删除） |
| 内核 | **不需要为 `-1` 加任何分支**。取消 `-1` 后，"续期处 `currentTime + timeout * 1000L` 在 `timeout < 0` 时会算出过去时间"这个问题只可能由"手工 `new DefaultAuthenticationManager(..., 非正数)`"触发 —— 装配期校验挡住了配置入口，而"绝对过期校验"又排在续期判断之前，使非正 timeout 下的续期分支**不可达**。因此这里**不加** `timeout > 0` 守卫：它是可被证明不可达的死代码，且写不出能判别它的测试（实测加上前后用例表现完全一致，见下条"反向验证"）。改为在代码注释里显式写下这段**隐含依赖**（"绝对过期校验必须保持在续期之前"），让将来调整判断顺序的人看到 |
| 仓储侧 | **四个仓储都不再有任何 `timeout` 语义分支**：`RedisSessionRepository.save/refreshByCredentials` 恢复为无条件带 TTL 的重载；`CaffeineSessionRepository.nanosUntilExpire` 删除溢出特判。它们现在都只依赖"传入的 timeout 必为正数"这一前置条件，并由装配期校验保证 |
| 与 P1-7 的交互 | Redis 的 Lua 脚本仍以 `ARGV[3] <= 0` 作为"不设置 TTL"的防御性分支（`listTimeoutSeconds`），但正常配置下恒为正值；该分支保留是为了脚本自身的健壮性，不是功能语义 |
| 测试 | `AuthProviderTimeoutTest` 6 个用例：`0` 拒绝 / **`-1` 拒绝**（本次决策的锁定点）/ `-2` 拒绝 / 正数与 null 可装配 / null→1800 / 正数原样下传并按 60 秒铸造。四个仓储的"永不过期"用例全部删除或改写为"**缺 `loginExpireTime` 时按已失效处理**" |
| 保留的既有用例 | `SingleSessionRepositoryTest.neverExpireSessionShouldStayValid` 是**改动前就存在**的，它锁的是缓存层 `LocalTimeCache.NEVER_EXPIRE` 的既有能力（与配置层是否允许 `-1` 无关），故保留并在注释中说明二者区别 |
| 反向验证 | 把装配期校验改成恒真（合法变异，命中 1 处）→ **三个拒绝用例同时变红**：`shouldRejectZeroTimeout:34`、`shouldRejectNeverExpireTimeout:45`、`shouldRejectOtherNegativeTimeout:55`，均报 `Expected IllegalArgumentException to be thrown, but nothing was thrown`。<br>**一次被自己否掉的尝试**：曾为内核续期加过 `this.timeout > 0` 守卫并配了用例 `shouldNeverRefreshWhenTimeoutIsNotPositive`，但反向验证**没能让它变红**（去掉守卫后用例照样通过）—— 原因是该分支在当前代码顺序下不可达（见上行"内核"）。进一步发现那条用例本身也不稳（把过期时间设成 `now + 1ms`，机器稍慢就自己先过期了，JDK 21 上如实报 `UnAuthorizedException`）。**结论：不可达的守卫 + 无法判别的测试一起删除**，只保留代码注释里的依赖说明 —— 留着一个"看着像防护、实则永不执行"的分支，正是本报告反复批评的那种假修复 |
| 历史实测（保留备查） | 本项在"支持 `-1`"阶段对真实 Redis（`127.0.0.1:6379`）做过实测，结论仍然有效且值得记录：`SET k v EX -1` → `ERR invalid expire time in set`；Spring Data `setIfAbsent(k,v,-1,SECONDS)`（SET NX）却**容忍** `-1` 并落成无 TTL，而 `set(k,v,-1,SECONDS)`（SETEX）报 `ERR invalid expire time in setex` —— **同一客户端库的两条写路径对 `-1` 行为不一致**。这正是"不要在框架里引入需要绕开底层怪癖的语义"的一个具体例证 |
| 边界 | 配置层只保证"进不来非正值"；仓储作为 SPI 仍可能被直接调用并传入非正值（自定义调用方）。仓储侧不做二次校验，属**有意的信任边界**：校验放在装配期一次，避免四个仓储各写一套重复判断（这也是 P1-7 结论里"四仓储强度不同"的同类教训——**能收敛到一处的校验就不要散落到四处**） |
| 未做 | P1-7（并发上限 check-then-act）在 `1.5.0` 已就地完成 3/4（Redis / Single / Caffeine 原子化），JDBC 残余另列 §4.3 第 13 行

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
- **状态**：`DONE`（`1.5.0`）

##### P1-9 实施记录（1.5.0）

**先取证（实测）** —— 三条指控全部证实：

| 指控 | 实测结果 |
|---|---|
| 类型漂移 | `Long 10001L` 经 JSON 往返变成 **`Integer`**；`(Long)` 强转抛 `ClassCastException`（`class java.lang.Integer cannot be cast to class java.lang.Long`） |
| 共享引用 | single / caffeine 的 `getSubject` 两次返回**同一实例**，且**篡改后回读受影响**（污染缓存） |
| 无往返测试 | 确认项目中不存在任何一次 `getSubject` 的 JSON 往返用例 |

| 项 | 内容 |
|---|---|
| loginId 类型契约 | 在 [`LoginSubject.setLoginId`](../tiny-security-core/src/main/java/org/tinycloud/security/context/LoginSubject.java) 上做**反序列化归一化**：整型（`Integer`/`Short`/`Byte`）一律归一为 `Long`；`Long` 原样；`String`/`Double` 不变（不做"看起来像数字就转"的猜测，避免有损转换与语义漂移）。因 Jackson 反序列化同样走 setter，**直接构造与 JSON 往返得到同一类型** |
| 防御性副本 | 新增 `LoginSubject.copy()`（浅拷贝）；single / caffeine 的 `getSubject` 改为返回副本 |
| 为什么 `copy()` 只做浅拷贝 | `extraInfo` 的引用语义在四种仓储下本就不同（内存版共享、Redis/JDBC 每次反序列化重建），深拷贝无法消除这一事实，反而增加开销；框架内部不修改 `extraInfo`，约定已写在方法注释里 |
| **顺带修掉的同源缺陷** | **TCK 直接抓到**：single 与 redis 的**有效性判定只看存储层 TTL、不看 `loginExpireTime`**，于是"存储层仍有效、但会话已过期"的凭证被判为**有效**（与 caffeine / jdbc 口径不一致）。redis 的 `clearInvalidCredentials`（在线列表清理）有同一问题，导致在线数虚高。两处均已改为与 `checkByCredentials` 同口径，并把判定抽成 redis 的 `hasValidSubject()` 供三处共用，避免再次分叉 |
| 反向验证 | ① 去掉 single 的 `loginExpireTime` 判定 → TCK **3 条变红**（`expiredSessionShouldBeTreatedAsAbsent`、`countValidOnlineSessionsShouldCountOnlyValidOnes`、`sessionWithoutExpireTimeShouldNotBeValid`）；② 去掉 caffeine 的副本 → TCK **2 条变红**（`getSubjectShouldReturnDefensiveCopy`、`getSubjectShouldNotReturnSharedInstance`） |
| **用例前提变更（重要）** | `DefaultAuthenticationManagerTest.shouldRejectStoreValidButExpiredSubjectOnBuiltInSingleRepository` 的**前置条件被本项修复消除**：它原先断言"内置仓储会把过期会话原样返回"，而修复后仓储自己就返回 `null`。已改写为两条 —— `shouldRejectExpiredSubjectWhenRepositoryDoesNotFilterIt`（用**不做过滤的假仓储**验证内核 P1-6 校验仍生效）与 `builtInRepositoryShouldAlsoFilterExpiredSubject`（固定"内置仓储也过滤"这一新事实）。**这不是迁就测试，而是修复改变了事实**：内核那道校验的价值本就在于守住 SPI 边界，而非依赖某个实现的当前行为 |

#### P1-10 · URL 鉴权模式不看 HTTP Method

- **证据**：[`AuthorizationEvaluator.checkUrlPermission()`](../tiny-security-core/src/main/java/org/tinycloud/security/authorization/AuthorizationEvaluator.java#L41-L50)（原先只用 `request.getRequestURI()` 做 Ant 匹配）
- **影响**："拥有 `GET /user` 读权限"等价于"拥有 `DELETE /user` 权限"。另外它拿的是含 context-path 的 URI，context-path 一改全部权限码失效（fail-closed，安全但难用）。
- **状态**：`DONE`（`1.5.0`）

##### P1-10 实施记录（1.5.0）

**方案（采纳"可选 Method"）**：权限码支持 `METHOD 路径` 写法（空格分隔、Method 大小写不敏感），**不写 Method 则匹配任意 Method**。这样既补上读写不分的漏洞，又让存量配置（裸路径，README 原要求）行为完全不变 —— 因此本项是**新增能力**，不是破坏性变更。

| 项 | 内容 |
|---|---|
| 解析规则 | `methodSeparatorIndex()` 只认**第一个空格**，且要求其左侧是合法 Method 前缀：`*`，或全字母且长度 ≤ 8。否则返回 -1，整条权限码按**裸路径**处理 |
| 为什么卡"全字母 + 长度 ≤ 8" | 避免把业务权限码误解析 —— 例如 `system:user:add` 含冒号、不是合法 Method，必须整条当路径；`DELETE`(6) / `OPTIONS`(7) 在长度内，超过 8 的必然不是 Method |
| `*` 通配 | `* /user/**` 与 `/user/**` 等义（显式写法的价值：表达"我知道能限 Method，但这里就是要全放"） |
| 兼容旧签名 | 保留 `matchPaths(Collection, String)` 两参重载，内部委托三参重载（`requestMethod = null`）。`null` 时只按裸路径匹配，不引入 Method 约束 |
| **context-path（决策：不修）** | 用户修改 context-path 属其自身部署行为，框架替他兜底反而引入"到底带不带前缀"的歧义。改为在 `README` §2.3.3 明确警告：权限码匹配**含 context-path** 的完整 URI，改 context-path 会导致既有权限码全部失配（fail-closed，不越权，但需同步调整配置） |
| **不换匹配器（决策：`WONTFIX`）** | **不把 `AntPathMatcher` 换成 `PathPattern`**。本项原本把"用 Spring 已解析的 `PathPattern` 替代裸 URI"列为修复方向，经实测**该方向是错的**：<br>① **它修不了它想修的问题**：`%2F` 之类的编码绕过与匹配器无关，根源在**输入源** —— `request.getRequestURI()` 返回的是**未解码**的原始 URI。实测两者行为完全一致：`/user/*` vs `/user/a%2Fb` 都是 `true`，`/**` vs `/user%2e%2e/admin` 都是 `true`。真要修得换输入源（改用 Spring 已解析的路径），而那是 `AuthorizationManager.authorize(...)` 的签名变更，属公开 API 变更，成本远大于换匹配器。<br>② **收益几乎为零**：逐条实测 23 组 pattern，现有词汇表（`/**`、`/user/*`、`/{id}`、`?`）两者结论**完全一致**；唯一实质好处是 PathPattern 支持正则路径变量（`{id:[0-9]+}`），框架目前没有任何地方需要。<br>③ **风险是真实的**：路径**中间**的 `**` 在 Ant 下正常匹配，在 PathPattern 下**直接抛 `PatternParseException`**（`No more pattern data allowed after {*...} or ** pattern element`）—— 存量权限码（如 `/user/**/edit`）会从"能匹配"变成"每次请求抛异常"，属**破坏性变更**。<br>④ 另有细微差异：连续双斜杠 `/user/*` vs `/user//list`（Ant=true / PP=false）。<br>**若将来确实需要**正则路径变量、或要修正编码绕过，应按「**先换输入源，再评估匹配器**」的顺序单独立项 |
| 先证缺陷 | 新增 6 条用例，改动前**4 条变红**，其中 `checkUrlPermissionShouldEnforceHttpMethodWhenSpecified:198` 的失败形态正是漏洞本身：`DELETE /user/**` 权限码在 GET 请求上返回 `true` |
| 反向验证 | 把 Method 比较变异为恒假（等价于"不看 Method"）→ 2 例变红，报错逐字为 `GET 请求不得被 DELETE 权限码放行 ==> expected: <false> but was: <true>` 与 `未授予 DELETE，不得放行 ==> expected: <false> but was: <true>`；还原后恢复绿 |
| 测试同步 | `AuthorizationEvaluatorTest` 17 例 → 23 例：Method 强制、读写分离、不写 Method 匹配任意、大小写不敏感、非 Method 前缀按裸路径、`*` 通配，各一条 |

#### P1-11 · 事件机制：失败路径监听器异常会顶掉原始异常；成功事件携带完整 token

- **证据**：
  - [`AuthProvider.java:334-342`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L334-L342)（`publishLoginFailure` 在 catch 块内，**未被单独 try/catch 保护** → 监听器抛异常会替换原异常）
  - [`AuthProvider.java:343-349`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L343-L349)（**成功路径已正确隔离**：单独 try/catch + WARN —— 此处无需改）
  - [`AuthProvider.java:346`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L346)（`LoginSuccessEvent` 携带**完整 token**，内含 credentials）
  - [`SpringSecurityEventPublisher`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/event/SpringSecurityEventPublisher.java)（同步 `publishEvent`，慢监听器阻塞请求线程）
- **修复方向**：失败路径同样隔离；`LoginSuccessEvent` 改为携带不可逆标识而非完整 token；发布策略可配置同步/异步。
- **状态**：`DONE（1/3）`（`1.5.0`）—— **失败路径隔离已完成**；「成功事件携带完整 token」与「发布策略可配同步/异步」两项**未做**（理由见下）

##### P1-11 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 本条只做 1/3 的理由 | 原文的修复方向有三条，但只有第一条是**缺陷**：后两条（改 `LoginSuccessEvent` 字段、发布策略可配）属**公开 API 变更 / 新特性**。`LoginSuccessEvent.getToken()` 是已发布 API，改成返回不可逆标识会让存量监听器（审计、绑定设备等）拿不到 token；而"事件里带 token"本身是**设计取舍**而非缺陷 —— 监听器与框架同进程、同信任域，能读到 token 的代码本来就能读到 `credentials`。故本版本按文档既定建议**只做失败路径隔离**这一半，另两条留待阶段 2 与事件机制一起重做 |
| 先证缺陷 | `AuthProviderEventTest` 新增 `shouldKeepOriginalExceptionWhenFailureListenerThrows`：让测试用发布器在 `publishLoginFailure` 里抛 `RuntimeException`，断言登录仍抛**原始**的 `TinySecurityException`（消息 `create auth failed`）。改动前如实变红：`Unexpected exception type thrown, expected: <TinySecurityException> but was: <RuntimeException>` —— 监听器异常**确实**顶掉了原始异常 |
| 修复 | catch 块内的 `publishLoginFailure` 加一层 `try/catch (Exception)` + `log.warn`，与下方成功路径的写法完全对齐；`throw ex` 移到内层 try 之外，保证原始异常必达 |
| 反向验证 | 把新增的 `catch (Exception publishEx)` 变异为 `catch (IllegalStateException publishEx)`（即不再吞掉 `RuntimeException`）→ 该例**变红**，报错与修复前逐字一致；还原后恢复绿。变异前先断言锚点命中数 = 1（本仓库曾两次因锚点命中 0 得到假验证） |
| 未做的两项 | 见上表第一行；已明确**不是**遗漏 |


#### P1-12 · `checkLogin()` 可能抛 `IllegalArgumentException`（→ HTTP 500）而不是 401

- **证据**：[`AuthProvider.checkLogin()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L459-L478)（原先无 try/catch）→ `checkByCredentials(this.getCredentials())` → 仓储的 `Assert.hasText(credentials, ...)` → `IllegalArgumentException`（**不是** `TinySecurityException`，因此异常解析器返回 null，交给 Spring 默认 500 处理）
- **触发条件（`1.5.0` 实测修正）**：本条原写的是"**JWT 验签通过但不含 `credentials` claim**"。JWT 已在 `1.5.0` 移除，该写法不复存在；但**缺陷本身仍在**，只是触发点换了 —— token 形态是 `credentials.signature`，凭证即分隔符左侧内容。`TokenSignUtil.sign` 用 `Assert.hasText` 拦住空凭证，然而**用同一 secret 自行计算 HMAC 即可绕过该断言**（同密钥的其他用途、或密钥泄露场景）。实测：`" " + "." + base64url(HMAC-SHA256(" ", secret))` 这种 token 会被 `verifyAndExtract` 原样返回为 `" "`，随后命中仓储断言。

  > **排查记录**：曾一度判断"JWT 移除后 P1-12 的前提已不成立、可以关闭"。**该判断是错的** —— 第一版探针用了假仓储（`checkByCredentials` 直接返回 `true`），恰好绕过了抛异常的那一步；换成内置 `SingleSessionRepository` 后缺陷立即复现。教训：**验证"缺陷是否仍可达"时，替身必须保真到会出问题的那一层**，否则否证是假的。
- **对照**：[`isLogin()`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L439-L447) 早已 catch `Exception` → 返回 false，是正确写法；`checkLogin()` 与它只该在"抛异常还是返回 false"上不同，对**异常输入的容错**必须一致。
- **修复**：`checkLogin()` 补 try/catch —— `UnAuthorizedException` 原样抛出（语义本就是未登录），其余异常按"未登录"处理并降为 debug 日志，最终统一抛 `UnAuthorizedException`（401）。
- **状态**：`DONE`（`1.5.0`）

##### P1-12 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 先证缺陷 | 新增 `AuthProviderCredentialsTest` 两例（用**内置** `SingleSessionRepository` + 已绑定请求上下文），改动前如实变红：`shouldRejectBlankCredentialsTokenWithUnauthorizedInsteadOf500:125` 与 `blankCredentialsShouldBeHaveConsistentlyBetweenIsLoginAndCheckLogin:140`，均报 `Unexpected exception type thrown, expected: <UnAuthorizedException> but was: <IllegalArgumentException>` |
| 修复 | `checkLogin()` 增加两层 catch：`UnAuthorizedException` 直接 rethrow；其余 `Exception` 记 debug 日志后置 `success = false`，由原有分支抛出 401 |
| 为什么不用 `Assert.hasText` 前置校验 | 那样只是把同一类判断散落到第二处；真正的语义是"任何导致无法确认登录态的异常都等价于未登录"，交给 catch 收口更彻底，也与 `isLogin()` 的既有写法对齐（**收敛到一处**，同 P1-8 的教训） |
| 反向验证 | 把该处的宽泛 catch 变异为 `catch (IllegalStateException e)`（即不再吞掉 `IllegalArgumentException`）→ 上述两例**同时变红**，报错与修复前逐字一致；还原后恢复绿。变异点已按字节索引精确定位（`catch` 与 `log.debug` 之间隔有两行注释，早期的行内正则锚点匹配失败、命中数为 0 —— 命中数为 0 的"验证"是假验证，已改为先断言命中数再执行） |
| 测试同步 | `AuthProviderCredentialsTest` 4 例 → 6 例；新增用例同时覆盖"401 而非 500"与"`isLogin`/`checkLogin` 行为一致"两个角度 |

#### P1-13 · `SimpleHash` 被当作"密码哈希"宣传

- **证据**：[`SimpleHash.java:10-24`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/SimpleHash.java#L10-L24)、README §2.5.3
- **问题**：支持 MD5/SHA-1 为一等算法名；"迭代"只是裸摘要链（**不是** PBKDF2/scrypt/Argon2/bcrypt），无内存硬度、无每用户随机盐（存在免盐构造器）、**没有任何校验 API**（调用方只能自己 `String.equals`，重新引入时序侧信道）。
- **修复方向**：README 中移出"密码哈希"章节，降级为"摘要工具"；密码哈希只保留 BCrypt，并考虑提供 `PasswordEncoder` SPI。
- **状态**：`DONE`（`1.5.0`）—— README 侧降级完成；**代码未改**（`SimpleHash` 本身保留，仅纠正定位与文档措辞）

##### P1-13 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 改动范围 | **纯文档**（`README.md` §2.5.3），零代码改动。节标题由「密码哈希与摘要算法」改为「**摘要算法与密码哈希**」，并把摘要算法排在前、密码哈希排在后 |
| 摘要工具加警告块 | 在 `SimpleHash` 示例上方加了显式警告：**是摘要工具、不是密码哈希、勿用于存口令**，并逐条写明理由（MD5/SHA-1 已不适用、`iterations` 非 KDF 无内存硬度、允许不加盐、无校验 API 会引入时序侧信道），并把用户**指引到 `BCrypt`** |
| 密码哈希章节收口 | BCrypt 段补一句正面理由（自带随机盐、work factor 可调、`checkpw` 恒定时间比较），让"该用哪个"有明确答案 |
| **顺带修掉 DOC-1** | 原示例用的是**根本不存在的类** `MD5Hash` / `Sha256Hash`（12 行示例全部无法编译，真实类名是 `SimpleHash`）；本次改写把这些示例**全部换成真实 API**，并补齐 `SM3Hash(...)` → `SimpleHash("SM3", ...)` 的统一写法。DOC-1 与 DOC-12 一并置 `DONE` |
| 验证（可编译） | 把 README 改写后的**全部示例逐行照抄**进一个临时类，用 JDK 17 对 `tiny-security-core/target/classes` 直接 `java` 单文件编译运行 → `README examples compiled & ran OK; checkpw=true`，随后删除临时文件。满足阶段 0 退出标准中「README 中的每条 API 示例都能实际编译通过」 |
| 验证（无残留） | `grep -n "MD5Hash\|Sha256Hash" README.md` → 无命中 |
| 未做的部分 | 原文"密码哈希只保留 BCrypt，并考虑提供 `PasswordEncoder` SPI"—— 提供 SPI 属**新功能**，不在本次（阶段 1 收尾）范围；`BCrypt` 的既有问题已定级 `WONTFIX`（见 P0-5 / P2-13） |

#### P1-14 · `AuthProvider.refreshByCredentials(credentials, subject)` 只延长存储层 TTL，不更新 `loginExpireTime`

- **证据**：[`AuthProvider.java:228-230`](../tiny-security-core/src/main/java/org/tinycloud/security/provider/AuthProvider.java#L228-L230)（原实现只有一行：`return this.sessionRepository.refreshByCredentials(credentials, subject, resolveTimeout());`）
- **问题**：该方法只把「存储层 TTL」延长为 `timeout`，**从不更新 `subject.loginExpireTime`**。而 `1.5.0` 给内核补上的「绝对过期校验」（`DefaultAuthenticationManager`）判定的正是 `loginExpireTime` —— 两套过期口径就此分叉：存储里的会话明明还有 TTL，用户却已经 401，**续期看起来"没生效"**。旧逻辑靠"下一跳顺手续期"把这条缝盖住了，所以问题一直被掩盖。
- **对照**：内核自己的滑动续期路径是**正确**的 —— [`DefaultAuthenticationManager.java:66-68`](../tiny-security-core/src/main/java/org/tinycloud/security/authentication/DefaultAuthenticationManager.java#L66-L68) 先 `subject.setLoginExpireTime(currentTime + timeout * 1000L)` 再 `refreshByCredentials(...)`。**缺陷只在公开 API 这一处**，修法即与内核口径对齐。
- **来源**：`1.5.0` 代码自审中发现，与 P1-8 推翻记录第 ② 条同源。
- **修复**：采用**方案 A**（同步更新 `loginExpireTime`）—— 先按 `resolveTimeout()` 推进时间戳再落库，使「存储层 TTL」与「绝对过期时间戳」两套口径合一，方法名与行为一致。
- **状态**：`DONE`（`1.5.0`）

##### P1-14 实施记录（1.5.0）

| 项 | 内容 |
|---|---|
| 方案选择 | 文档给了 A（同步更新 `loginExpireTime`）/ B（标记废弃）两条路。**采用 A**：与 P1-8「收敛到一处」的教训一致 —— 让两套过期口径并存，等于把这个缺陷留在原地只是加个警告；且内核自己的续期路径本就是「先 set 再 refresh」，A 只是让公开 API 与内核对齐，不引入新语义 |
| **实测比原描述更严重** | 原条目判断症状是"401"。**实测在 `single` 仓储下更糟**：`SingleSessionRepository.isCredentialValid` 判定的也是 `loginExpireTime`，时间戳停在过去时 `getSubject` **直接返回 `null`** —— 会话根本读不回来（`checkByCredentials` 同样返回 false），而不是"读到了但被判过期"。这与 TCK 第一轮抓出的 single/redis「只看存储层 TTL、不看 `loginExpireTime`」是同一处判定，方向相反的另一面 |
| 用例设计上的两个讲究 | ① 刻意用**内置** `SingleSessionRepository` 而非假仓储 —— 用假仓储验证可达性会得到假结论（P1-12 教训）；② `getSubject` 返回的是**副本**（P1-9），所以**不能**靠"改动读出来的对象"来伪造过期状态（第一版用例正是这么写的、因此失真），必须直接构造 subject 传给 `refreshByCredentials`，这也正是该公开 API 的真实调用方式 |
| 先证缺陷 | 新增 `AuthProviderRefreshTest`（3 例），改动前如实变红 2 例：`refreshShouldExtendLoginExpireTime:78`（`loginExpireTime` 仍停在过去：`1792134007236`）与 `refreshedSessionShouldSurviveKernelAbsoluteExpiryCheck:101`（刷新后 `getSubject` 返回 `null`，会话不可达） |
| 反向验证 | 把新增的 `if (subject != null)` 变异为 `if (false)`（即整段更新都不执行）→ 上述两例**同时变红**，报错与修复前逐字一致；还原后恢复绿。变异前先断言锚点命中数 = 1 |
| 边界处理 | `subject == null` 时不抛 NPE，退化为纯 TTL 延长（`refreshShouldTolerateNullSubject` 锁定） |
| 测试同步 | core 306 → **309**（新增 A1 类 3 例）；全部既有用例保持绿 —— 尤其是 `DefaultAuthenticationManagerTest`，证明修复没有反向影响内核自身的续期路径 |
| 兼容性影响 | `loginExpireTime` 会被**改写**（推进到 `now + timeout`），已在方法 javadoc 显式声明。调用方若曾自行设置更长的过期时间，现在会被收敛为 `timeout` —— 这正是本次「口径合一」的目的，属修正而非能力削减 |


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
| P2-13 | jBCrypt 0.4 遗留写法（`1.5.0` 已实测复现）：`char64` 差一 —— `index_64.length`=128 而边界写作 `>`，`char64((char)128)` → `ArrayIndexOutOfBoundsException`；`$2b$`/`$2y$` → `IllegalArgumentException`（PHP `password_hash`、新版 OpenBSD 产物无法校验）；畸形 hash 抛 `StringIndexOutOfBoundsException`/`NumberFormatException` 而非返回 `false`；`checkpw(null, hashOf("null"))` → `true`；`gensalt` 只校验上界、每次 `new SecureRandom()` | [`BCrypt.java:397-401`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L397-L401)、[`:686-726`](../tiny-security-core/src/main/java/org/tinycloud/security/util/secure/BCrypt.java#L686-L726) | **定级修正**：本类在 `src/main/java` 中**零引用**（仅有自带的 `main()` 演示方法），不在认证链路上，影响面限于主动调用者 —— 由 P0-5 降级合并至此。若修，最小改动是 `char64` 的 `>` → `>=` | `WONTFIX` |
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
| DOC-1 | ~~README **宣传了不存在的类** `MD5Hash` / `Sha256Hash`（12 行示例代码全部无法编译；真实类名是 `SimpleHash`）~~ ✅ **`1.5.0` 已完成**（随 P1-13 一并改写为真实 API，并逐行编译验证通过） | [`README.md:620`](../README.md#L620) | `DONE` |
| DOC-2 | README 示例用 `I18nUtils.getMessage(...)`，该类**全项目不存在** | [`README.md:505-515`](../README.md#L505-L515) | `TODO` |
| DOC-3 | README 用 `authProvider.deleteTokenByLoginId(...)`，真实方法名是 `deleteByLoginId` | [`README.md:334`](../README.md#L334)、[`:341`](../README.md#L341) | `TODO` |
| DOC-4 | README 称 `AuthUtil.getLoginId()` **未登录返回 null** —— 与 1.4.0 破坏性变更（改为抛异常）和代码**完全相反**；示例第 282 行 `securityContext == null ? null : ...` 的写法同样建立在"可能返回 null"的错误前提上 | [`README.md:277`](../README.md#L277)、[`:280`](../README.md#L280)、[`:282`](../README.md#L282) | `TODO` |
| DOC-5 | README §2.5.1 教用户"把 token 放在 URL 参数里传"，但 `enable-url-token` 默认 **false** → 照做必然 401，且未提示需开启 | [`README.md:525-543`](../README.md#L525-L543) | `TODO` |
| DOC-6 | README 徽章写 **JDK 8+**，pom 实际 `source/target=17`（README.en 写的是 17） | [`README.md:8-10`](../README.md#L8-L10) vs [`pom.xml:38-40`](../pom.xml#L38-L40) | `TODO` |
| DOC-7 | 引用了**不存在的文档**：`docs/project-analysis-2026-08.md`、`docs/security-audit-and-roadmap-2026-09.md`（`docs/` 目录此前不存在） | [`CHANGELOG.md:91`](../CHANGELOG.md#L91)、[`README.en.md:263`](../README.en.md#L263) | `TODO` |
| DOC-8 | README 残留旧类名 `PermissionInfoInterfaceImpl`（接口早已改名 `AuthorizationInfoGet`） | [`README.md:162`](../README.md#L162)、[`:448`](../README.md#L448) | `TODO` |
| DOC-9 | CHANGELOG 声称已清理 `BCrypt`/`SimpleHash`/`SM3Hash`/`SM3ConvertUtil` 的 `main()`/`System.out`，实际 `BCrypt.main` 还在 | [`CHANGELOG.md:85`](../CHANGELOG.md#L85) vs P3-1 | `TODO` |
| DOC-10 | `README.en.md` 是"精简镜像"但缺少 `@Ignore`、`enable-url-token`、异常处理等章节，且同样引用不存在的 docs | 两份 README 对比 | `TODO` |
| DOC-11 | 未说明 `t_auth_storage.sql` 的位置与导入方式，也未说明 `login_subject` 的 5000 字符上限 | [`t_auth_storage.sql`](../tiny-security-boot-starter/src/main/resources/sql/t_auth_storage.sql) | `TODO` |
| DOC-12 | ~~README §2.5.3 把 `SimpleHash`（含 MD5/SHA-1）列在"密码哈希"语境下推荐~~ ✅ **`1.5.0` 已完成**（同 P1-13：加警告块、降级为摘要工具、指引到 `BCrypt`） | 同 P1-13 | `DONE` |
| DOC-13 | 缺少一份"配置项全表 + 默认值 + 生效条件"（`AuthProperties` 有 20+ 项，README 只列了一部分） | `AuthProperties` | `TODO` |
| DOC-14 | 用户可见文档未说明 **`AuthUtil` 只能在持有当前请求的线程上使用**：`@Async` / `Callable` / `DeferredResult` / MQ 消费线程里调用会抛 `UnAuthorizedException`，应改注入 `AuthProvider`。该边界只在 CHANGELOG 与内部文档里写了，README / README.en 的 `AuthUtil` 章节一字未提（见 P1-3 的定级修正） | [`README.md:275-281`](../README.md#L275-L281)、[`README.en.md:221-226`](../README.en.md#L221-L226) | `TODO` |
| DOC-15 | `README.en.md` 称 "`AuthUtil` is a static facade delegating to the framework context" —— P1-1/P1-2 之后它**不再是静态门面**（门面 Bean 已删除，`TinySecurityFacade` 降为包级私有），实为"每次调用从当前请求的容器解析 `AuthProvider`" | [`README.en.md:221`](../README.en.md#L221) | `TODO` |
| DOC-16 | ~~README / README.en 未说明 `tiny-security.timeout` 的取值语义~~ ✅ **`1.5.0` 已完成**：两份 README 的配置示例都在 `timeout: 1800` 上方补了「只允许正整数，0 或负数会在启动时报错」的说明。**注**：本条原描述含"`-1` 为永不过期"，该语义已在 P1-8 推翻 | [`README.md`](../README.md)、[`README.en.md`](../README.en.md) | `DONE` |

---

### 3.6 ENG / TST —— 工程与测试

| ID | 问题 | 证据 | 建议 | 状态 |
|---|---|---|---|---|
| ENG-1 | ~~**完全没有 CI**：无 `.github/`、无任何 workflow。一个要发布到 Maven Central 的双分支库全靠手跑 `mvn test`~~ ✅ **`1.5.0` 已完成** | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | 见下方"实施记录" | `DONE` |
| ENG-2 | 双分支（`master`=SB2/javax、`springboot3`=SB3/jakarta）靠**手工 cherry-pick** 同步，历史上已出现"需备份 tag""合并后要人工确认未误引入 jakarta"等高风险动作；Spring Boot 2.7 上游 OSS 支持已于 2023-11 终止 | [`.workbuddy/memory/2026-08-08.md`](../.workbuddy/memory/2026-08-08.md) | 宣布 SB2 分支 EOL（只留安全补丁），精力回收 | `TODO` |
| ENG-3 | `AuthAutoConfiguration` 用**字段注入**（`@Autowired private AuthProperties`），可测试性差；`@ConditionalOnBean(StringRedisTemplate.class)` 未配 `@AutoConfigureAfter(RedisAutoConfiguration.class)`，存在装配顺序风险 | [`AuthAutoConfiguration.java:113-118`](../tiny-security-boot-starter/src/main/java/org/tinycloud/security/AuthAutoConfiguration.java#L113-L118) | 后续重构为构造注入 + 显式排序 | `TODO` |
| TST-1 | **没有任何 MockMvc / 真正跑过拦截器的集成测试** —— 两个"端到端"测试都是手工构造 `SecurityContext` 再存进仓储来**模拟**拦截器。P0-1 这类"拦截器↔门面"回归在结构上根本发现不了 | `EndToEndFlowTest`、`TinySecurityAutoConfigurationTest` | 补 MockMvc 全链路测试（含路径排除、异常翻译） | `TODO` |
| TST-2 | **零测试的生产类**：`TinySecurityHandlerExceptionResolver`、`CookieUtil`、`VersionUtil`、`CommonUtil`、`HexUtil`、`SpringSecurityEventPublisher`（没有任何用例断言事件真的被发布）、`AuthProperties`（仅 2 项绑定）、以及 **`AuthAutoConfiguration.addInterceptors` 的全部逻辑**（`AnnotationUtils` 已于 `1.5.0` 补齐 9 例、`WebRequestUtils` 已随 P0-6 补齐，均从本清单移除） | 逐类 grep 确认 | 按 §4.2 补齐 P0 相关部分 | `TODO` |
| TST-3 | **空转 / 永真断言**（抽查代表）：`AuthAutoConfigurationTest.java:96-97` 的 `isInstanceOf(SessionRepository.class)` 恒真；`AuthProviderCookieTest.java:34-43` 名为"验证非 Web 线程写 Cookie 不 NPE"，但 `enableCookie` 默认 false → **根本没走到写 Cookie**（1.3.2 修的 NPE 已失去回归保护）；`CaffeineSessionRepositoryTest.java:91-102` 改的是存进去的同一个对象引用，`refresh` 改成空实现也照样绿；`DefaultExceptionTranslatorTest.java:50-57` 名为"code 缺失兜底"，实际兜底分支从未进入；`DefaultAuthenticationManagerTest.java:86-106` 号称测 `<=` 边界，实际恒小于 | 各测试文件 | 逐个修正为可证伪的断言 | `TODO` |
| TST-4 | **静态状态污染 / 并行不安全**：~~`AuthUtil.facade` 是全局静态被 6 个测试类写~~ ✅ **`1.5.0` 已随 P1-1/P1-2 去静态化**；残留：`AuthAutoConfigurationTest` 建 9 个上下文却**没有 `@AfterEach`**，全项目无 `junit-platform.properties` / `@ResourceLock`，`ThreadLocalSecurityContextRepository` 的 ThreadLocal 仍可能跨用例残留。一旦开启并行就会出现"用户串号"式污染 | 各测试文件 | ~~去静态化（随 P1-1/P1-2）~~；残留部分补 `@ResourceLock` 与清理 | `DOING` |
| TST-5 | ~~H2 建表语句**内联复制**在测试里，从不使用随包发布的 `t_auth_storage.sql`~~ ✅ **`1.5.0` 已完成**：新增 `AuthStorageDdl`，从**随包发布的** `sql/t_auth_storage.sql` 解析建表语句（括号配对扫描，非正则）并做 MySQL→H2 方言归一化；转换后若缺少 `credentials` 唯一约束则**直接抛异常**（不让"转换失败"伪装成"测试通过"）。TCK 的 Jdbc 子类已改用它 | `JdbcSessionRepositoryContractTest` | ~~让测试加载真实 SQL 脚本~~ | `DONE` |
| TST-6 | Redis 仓储测试全 Mockito，无真实 Redis → TTL / 原子性 / 序列化全未验证。**`1.5.0` 部分收敛**：已建 `RedisSessionRepositoryContractTest`，可在本地对真实 Redis 跑完整 TCK（20 例，默认按开关跳过）；**仍未引入 Testcontainers**，CI 中依旧不跑真实 Redis | `RedisSessionRepositoryTest` | 引入 Testcontainers 或嵌入式 Redis（至少覆盖 TTL 与序列化往返） | `DOING` |
| TST-7 | 白盒反射测试脆弱：`SingleSessionRepositoryTest` 反射写 `LocalTimeCache.expireMap`；`SessionRepositoryLifecycleTest` 反射读 `executorService` 字段名 | 各测试文件 | 改为通过公开 API 或提供 `isShutdown()` 之类可观测点 | `TODO` |
| TST-8 | ~~**没有仓储契约 TCK**（同一套用例跑 4 个实现）~~ ✅ **`1.5.0` 已完成**：新增 `SessionRepositoryContractTest` 抽象基类（20 个契约用例，覆盖读写往返、凭证碰撞、loginId 类型、副本语义、过期判定、续期、删除、在线统计、并发上限），四个实现各一个子类；**建立过程中直接抓出 single 与 redis 的两个同源缺陷**（详见 P1-9 实施记录） | — | ~~建 `SessionRepositoryContractTest` 抽象基类~~ | `DONE` |
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
| 4 | ~~`BCrypt` 契约修正~~ ⏭️ **`1.5.0` 评估后不修改**（定级修正：零引用的第三方工具类，原条目两条"缺陷"为误报） | ~~P0-5、P2-13 部分~~ |
| 5 | ~~`WebRequestUtils` 默认值~~ ✅ **`1.5.0` 已完成** | P0-6 |
| 6 | ~~`SM3Hash` null salt + 失败不再静默~~ ✅ **`1.5.0` 已完成** | P0-7 |
| 7 | 删死代码与违规残留 | P3-1、P3-2、P3-5、P3-6 |
| 8 | **文档纠错一次性做完** | DOC-1 ~ DOC-13 |
| 9 | ~~**加 CI**~~ ✅ **`1.5.0` 已完成** | ENG-1 |

**退出标准**：CI 绿灯；P0 全部收敛（`DONE`，或经复核判定 `WONTFIX` —— 当前仅 P0-5）；README 中的每条 API 示例都能实际编译通过。

#### ENG-1 实施记录（`1.5.0`）

新增 [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)：`master` / `springboot3` 的 push 与 PR 触发，JDK **17 / 21** 矩阵（`fail-fast: false`），执行 `mvn -B -ntp verify -Dgpg.skip=true`，并上传 JaCoCo 报告为构建产物。父 pom 增加 JaCoCo，`LINE` 覆盖率门槛 `jacoco.line.minimum = 0.50`（实测 core 68.4% / starter 58.1%，取值保守，意在防止无声退化而非逼着刷覆盖率）。

**建立 CI 的过程本身发现了两个此前不可见的问题：**

1. **`mvn -B verify` 在 CI 里根本跑不通** —— `maven-gpg-plugin` 的 `sign-artifacts` 绑定在 `verify` 阶段，无 GPG 私钥必然失败。故命令必须带 `-Dgpg.skip=true`。这解释了为什么此前一直只跑 `mvn test`。
2. **JDK 21 下 9 个测试报 Mockito 错误**（真因不是 JDK，而是依赖冲突）：
   - `assertj-core:3.24.2` 传递进来的 `byte-buddy:1.12.21` 与 `mockito-core:5.7.0` 需要的 `1.14.9` **处在同一依赖深度**，Maven 按「声明顺序」选中了前者（assertj 在前）；
   - 报错为 `Java 21 (65) is not supported by the current version of Byte Buddy which officially supports Java 20 (64)`；
   - 本项目**未 import `spring-boot-dependencies` BOM**，没有 BOM 来仲裁该冲突 —— 这是根因；
   - 修复：父 pom **`import` `spring-boot-dependencies` BOM**。**仅影响构建期的依赖仲裁，不改变发布产物的依赖声明。**
   - **为什么是 BOM，而不是写死 `bytebuddy.version`**：根因是本项目**从未 import Spring Boot BOM** —— 逐条声明构件只能拿到「传递版本」，拿不到用于「冲突仲裁」的 `dependencyManagement`，于是同深度冲突只能靠声明顺序碰运气。三个方案的实测对比：

     | 方案 | 能否修好 JDK 21 | 是否结构性 | 影响依赖条目 |
     |---|---|---|---|
     | 写死 `bytebuddy.version=1.14.19` | ✅ | ❌ 下一个冲突仍会复现 | 1 |
     | **import `spring-boot-dependencies` BOM**（采用） | ✅ | ✅ Spring Boot 自己的仲裁生效 | 12 |
     | 升级 `springboot.version` 到 3.3.12 | ✅ | ❌ 冲突结构不变 | 大量 |

     第三条需要特别说明：3.3.12 之所以也能过，是因为它带的 `assertj-core:3.25.3` 传递的是 `byte-buddy:1.14.11`（≥1.14.10 即支持 Java 21），**冲突结构一模一样**（assertj 依然靠声明顺序胜出），只是两个候选版本恰好都够新 —— 属于"被版本号顺带治好"，版本组合一旦再错开就会原样复现。
   - **BOM 方案的可见影响**：除 `byte-buddy` → `1.14.19` 外，还把 11 个传递依赖对齐到 Spring Boot 3.2.12 自己管理的版本 —— `netty-*`（9 个）`4.1.107.Final → 4.1.115.Final`、`reactor-core 3.6.4 → 3.6.12`、`micrometer-* 1.12.12 → 1.12.13`、`slf4j-api 2.0.2 → 2.0.16`。方向上都是**升到 Spring Boot 期望的版本**（原先那些是 lettuce 等传递依赖带进来的、比 Spring Boot 期望的更旧），属于修正而非引入风险。`jakarta.servlet-api` 与 `caffeine` 因在 `dependencyManagement` 中显式声明（优先级高于 BOM），**版本未变**。

**遗留提醒**：若把本 workflow cherry-pick 到 `master`（SB2/javax）分支，需同时带上父 pom 的 BOM import，否则该分支的 JDK 21 矩阵会复现上述 Mockito 失败。另：仓库**没有 Maven Wrapper**，CI 用的是 runner 自带的 Maven；如需锁定 Maven 版本可后续补 `mvn wrapper:wrapper`。

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
| 2 | ~~`SecurityContext` 懒加载 + 请求级缓存（治 P0-1 的类根因）~~ ✅ **`1.5.0` 已随 P0-1 完成** | P0-1（收尾） |
| 3 | ~~异步上下文传播~~ ❌ **判定为使用方式问题，不做**（`1.5.0` 决策） | P1-3 |
| 4 | ~~绝对过期校验下沉内核；`timeout` 语义统一~~ ✅ **`1.5.0` 已完成**（拆出 P1-7，见下） | P1-6、P1-8 |
| 5 | ~~静态门面去化（`AuthUtil` 与 `AuthProvider` 解耦）~~ ✅ **`1.5.0` 已完成** | P1-1、P1-2 |
| 6 | ~~注解查找沿父类/接口上溯~~ ✅ **`1.5.0` 已完成** | P1-4 |
| 7 | ~~Cookie 登出与 SameSite 语义修正~~ ✅ **`1.5.0` 已完成**（删除指令补齐 `Secure`/`SameSite`；`logout(request)` 增加同一性校验） | P1-5 |
| 8 | ~~仓储契约收紧 + **建 TCK**~~ ✅ **`1.5.0` 已完成**：TCK 已建成并跑通四个实现（20 例 × 4）；过程中抓出 single / redis 的同源缺陷与 JDBC 的已知残余（并发上限）。**JDBC 并发上限的闭合拆到第 13 行**（需破坏性 DDL） | ~~P1-9~~、~~TST-8~~、~~TST-5~~、TST-6（部分） |
| 9 | ~~事件机制修正~~ ✅ **`1.5.0` 已完成（1/3）**：**失败路径隔离**已做（监听器异常不再顶掉原始异常，含反向验证）。另两条（`LoginSuccessEvent` 改带不可逆标识、发布策略可配同步/异步）判定为**公开 API 变更 / 新特性**，留待阶段 2 与事件机制一并重做 —— 理由见 P1-11 实施记录 | ~~P1-11~~ |
| 10 | ~~补 MockMvc 全链路集成测试~~ | TST-1、TST-2 |
| 11 | ~~`checkLogin()` 对"验签通过但凭证为空白"的 token 返回 500 而非 401~~ ✅ **`1.5.0` 已完成**（触发条件按实测改写：原文的"JWT 不含 claim"随 JWT 移除已不适用） | P1-12 |
| 12 | ~~`SimpleHash` 从 README「密码哈希」章节降级为「摘要工具」~~ ✅ **`1.5.0` 已完成**（另顺带修掉 DOC-1：原示例的 `MD5Hash`/`Sha256Hash` 是**不存在的类**，已全部换成真实 API 并逐行编译验证） | ~~P1-13~~、~~DOC-1~~、~~DOC-12~~ |
| 13 | **JDBC 并发登录上限的真正闭合** —— 唯一可行且**不需要事务**的设计：给 `t_auth_storage` 加 `slot` 列 + `UNIQUE (login_id, slot)`，登录时依次尝试 `slot = 1..max`，唯一键冲突即该槽位被占、全部被占即拒绝；每条 `INSERT` 各自靠唯一索引保证原子，**无需事务**，会话删除/过期后槽位自动释放。代价是**破坏性 DDL**（含既有行回填）与登录路径上最多 `max` 次 INSERT 重试。**当前建议：暂不做** —— 默认 `store-type` 是 `single`（已原子），`jdbc` 为显式选用；且症状是"并发下偶发超限"而非"登不进来"，不值得为它引入破坏性 DDL | P1-7（残余） |
| 14 | ~~**`AuthProvider.refreshByCredentials(credentials, subject)` 语义收口**：该方法只延长**存储层** TTL，从不更新 `subject.loginExpireTime`，导致"存储层 TTL"与"过期时间戳"两套口径分叉；内核补上绝对过期校验后这种分叉会表现为 401（旧逻辑靠下一跳顺手续期把缝补上了，问题一直被掩盖）。~~ ✅ **`1.5.0` 已完成**（采用方案 A：同时按 `resolveTimeout()` 推进 `loginExpireTime`，两套口径合一。**实测比原描述更严重**：`single` 仓储下 `getSubject` 直接返回 `null`，会话根本读不回来，详见 P1-14 实施记录） | ~~P1-14~~ |

**退出标准**：4 个仓储通过同一套契约测试；MockMvc 全链路测试覆盖 认证→授权→异常翻译 三条主路径；`AuthUtil`/`AuthProvider` 在手工 `new` 与自定义 Bean 场景下都可用。

### 4.4 阶段 2 · 做深授权（1.6 → 2.0，真正的护城河）

| 顺序 | 事项 | 说明 |
|---|---|---|
| 1 | `AuthorizationInfoGet` 从「`Set<String>` 裸集合」升级为结构化 `AuthorizationModel`（角色 + 权限码 + 数据范围 + 权限版本号），保留旧 SPI 适配器做兼容 | 这是产品级能力的地基 |
| 2 | **权限缓存与失效**：请求级缓存（必做）+ 可选短 TTL 本地缓存 + `refreshPermission(loginId)` 主动失效钩子 | 当前 README 说"框架不做缓存，请自行处理"，等于把最麻烦的部分推给用户，也放弃了产品价值 |
| 3 | **数据权限**：`@DataScope(deptAlias=..., userAlias=...)` + MyBatis/JPA 拦截器 | **最有可能"别人没有"的能力** |
| 4 | ~~URL 模式补 HTTP Method~~ ✅ **`1.5.0` 已完成**（可选 Method，存量裸路径行为不变）。~~`PathPattern` 替换~~ ⏭️ **`WONTFIX`**：实测它修不了编码绕过（那是输入源的问题）、现有词汇表两者结论完全一致、而中间的 `**` 会让存量权限码直接抛异常（详见 P1-10 实施记录） | P1-10 |
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
| 2 | **三套 API 面怎么收敛？** | 保留 `AuthProvider`（唯一实例门面）+ `AuthUtil`（静态便捷外观，但**不再依赖可变静态全局**），**删除 `TinySecurityFacade` 的公开性**（降为内部实现） | 现在三套语义重复且靠静态桥互连，是 P1-1/P1-2/TST-4 的共同根因。**`1.5.0` 已按本决策落地，见 P1-1 / P1-2 实施记录** |
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

**建议**：CI 已建好（ENG-1），把 TST-3 里每一条都补一个"能证伪"的测试，用运行结果替换本文档中基于阅读的判断。

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
