# tiny-security 开发交接与进度速览（1.5.0）

> **用途**：换机器/换人接手时，用最少的时间恢复到"可以继续干活"的状态。
> 本文只讲**怎么恢复环境**、**已经做到哪**、**下一步做什么**；详细论证与实测数据在
> [`tiny-security-分析报告与演进路线.md`](./tiny-security-分析报告与演进路线.md)（演进 SSOT）。
>
> 最后更新：`1.5.0` 开发期，HEAD `038b258`。

---

## 0. 先确认没有未提交的工作

```bash
git status          # 应为 clean
git log -1 --oneline
```

交接时状态：**工作区干净、与 `origin/springboot3` 完全同步（0 个未推送提交）**。
换机器后 `git clone` + `git checkout springboot3` 即可完整恢复。

---

## 1. 新机器环境准备

| 项 | 要求 | 说明 |
|---|---|---|
| 分支 | `springboot3`（主开发分支） | Spring Boot 3 / Jakarta。`master` 是 SB2/javax 分支，**继续维护但不在上面开发**（`1.5.0` 决策 4：不做 EOL） |
| JDK | **17 必须**，21 也需能跑通 | 编译目标 17；CI 跑 17/21 矩阵 |
| Maven | 3.9+（无 wrapper） | 仓库没有 `mvnw`，用本机 `mvn` |
| 构建命令 | `mvn -B clean verify -Dgpg.skip=true` | **`-Dgpg.skip=true` 不可省**：GPG 插件绑在 `verify`，无密钥会失败 |
| 仓库 | https://github.com/llllllxy/tiny-security.git | 模块：`tiny-security-core`（artifactId `tiny-security-core3`）、`tiny-security-boot-starter`（`tiny-security-boot3-starter`） |

```bash
git clone https://github.com/llllllxy/tiny-security.git
cd tiny-security && git checkout springboot3
mvn -B clean verify -Dgpg.skip=true     # 基线：core 305（含 20 skipped）+ starter 16
```

**JDK 21 的一个坑**：父 pom 已 `import` `spring-boot-dependencies` BOM 用于依赖仲裁（`byte-buddy` 冲突曾导致 JDK 21 下 9 个 Mockito 用例失败）。**不要删这个 import**。

**本地可选：对真实 Redis 跑完整契约测试**（默认跳过，CI 无 Redis）：

```bash
export TINY_SECURITY_TCK_REDIS=1
export TINY_SECURITY_TCK_REDIS_HOST=127.0.0.1
export TINY_SECURITY_TCK_REDIS_PORT=6379
export TINY_SECURITY_TCK_REDIS_PASSWORD=<你的密码>
export TINY_SECURITY_TCK_REDIS_DATABASE=15      # 默认 15，刻意避开 0
mvn -B test -pl tiny-security-core -am -Dtest=RedisSessionRepositoryContractTest
```

测试只清理 `tiny:security:*` 前缀的 key，**不执行 FLUSHDB**。

**换行符**：`core.autocrlf=true`，仓库树是 CRLF。用脚本/工具写文件后若出现"整个文件都变了"的 diff，先归一化再提交：

```powershell
[System.IO.File]::WriteAllText($p, [regex]::Replace([System.IO.File]::ReadAllText($p), "(?<!\r)\n", "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
```

---

## 2. 1.5.0 做完了什么

`1.5.0` 是一条"破坏性收敛"版本，主线是**把散落在各处的判定收归一处**。

### 2.1 已完成的批次（每批一个提交，均已推送）

| 提交 | 内容 | 关键点 |
|---|---|---|
| `8c764bf` | P1-4 注解查找上溯父类/接口 | 修 fail-open：注解写在父类/接口时会被判定"无注解"而**直接放行** |
| （更早） | JWT 移除、`credentials-style` 删除、P0-1/2/3/4/6/7、ENG-1 CI | 见 CHANGELOG 的 1.5.0 段 |
| `35f5f74` | **P1-6 + P1-7 + P1-8**（破坏性变更） | 见 §2.2 |
| `0056729` | P1-12 `checkLogin()` 500 → 401 | 空白凭证 token 会命中仓储断言抛 `IllegalArgumentException`（非 `TinySecurityException`）→ Spring 500 |
| `f51fe44` | P1-10 URL 鉴权补 HTTP Method | 此前 `GET /user` 权限等价于 `DELETE /user` 权限 |
| `d0c1a54` | P1-5 Cookie 登出 | `SameSite=None` 时删除指令被浏览器忽略 → "登出后仍是登录态" |
| `038b258` | **TCK + P1-9 + TST-5** | 见 §2.3 |
| `4c80aa3` | P1-11（1/3）+ P1-13 + DOC-1/DOC-12 | 失败路径事件隔离；README 摘要/密码哈希降级（顺带修掉示例里的**不存在类** `MD5Hash`/`Sha256Hash`） |
| `ed6f372` | **P1-14** `refreshByCredentials` 口径收口 | 只延长存储层 TTL、不推进 `loginExpireTime`；内核补绝对过期校验后表现为续期"没生效"，`single` 下 `getSubject` 直接返回 `null` |
| （本次） | **P2-7 / P2-9 / P2-11 + P3-1 / P3-2 / P3-5 / P3-6 / P3-7 + 全部剩余 DOC** | 见 §2.5 |

### 2.2 `35f5f74`（P1-6 / P1-7 / P1-8）—— 破坏性变更，务必知道

1. **P1-6 会话绝对过期校验下沉内核**：`DefaultAuthenticationManager` 原先只判"剩余 TTL 是否 ≤ 20% 阈值"，**从不判是否已过期**；而续期条件对已过期会话恒成立 → **过期会话会被改写成 `now + timeout` 无限复活**。已在内核加 `expireTime <= now → 401`。
2. **P1-7 并发登录上限原子化**：Redis 用 Lua 脚本（判上限+入列+TTL 一次执行）；single/caffeine 把 count 挪进已有 `onlineLock`；**JDBC 未闭合**（见 §4）。
3. **P1-8 `timeout` 语义收敛为「只允许正数」**：`0` 与一切负数（**含 `-1`**）装配期直接报错。开发中途曾实现过"`-1` = 永不过期"，**已整体推翻**（理由见文档 P1-8 推翻记录）。

### 2.3 `038b258`（TCK / P1-9 / TST-5）

- **TCK 建成**：`SessionRepositoryContractTest` 抽象基类（20 个契约用例），四个实现各一个子类。
- **TCK 第一轮就抓出两个同源缺陷**：`single` 与 `redis` 的有效性判定**只看存储层 TTL、不看 `loginExpireTime`**；`redis` 的在线列表清理同病 → 在线数虚高。均已修复。
- **P1-9**：`getSubject` 返回**副本**（原先内存版返回共享实例，改一下会污染缓存）；`loginId` 反序列化**归一化为 `Long`**（原先 `Long 10001` 经 JSON 往返变 `Integer`，`(Long)` 强转抛 `ClassCastException`）。
- **TST-5**：Jdbc 测试改为加载**随包发布的** `sql/t_auth_storage.sql`（不再内联复制 DDL）。

### 2.5 本次批次（P2 + P3 + DOC 收尾）

| 项 | 内容 | 关键点 |
|---|---|---|
| **P2-7** | `getToken()` 前缀语义与 `login()` 对齐 | 此前 `getToken()` 返回**去前缀**裸值，放回请求头会 401；现返回带 `Bearer ` 前缀值，裸值走新增的 `getRawToken()`。**行为变更**，已入升级清单 |
| **P2-9** | `SameSite=None` + `cookie-secure=false` 告警 | 浏览器会丢弃该 Cookie（症状同 P1-5）；只 WARN、不擅自改用户配置 |
| **P2-11** | `token-secret` 短于 32 字节告警 | 只 WARN、**不阻止启动**（强制长度会破坏存量配置） |
| **P3-1** | 删 `BCrypt.main` + 5 处 `System.out` | 生产代码 `main`/`System.out`/`printStackTrace` 现均为 0 处 |
| **P3-2** | **删 `SM3ConvertUtil`（560 行）** | 仅 3 个方法被用，其余约 540 行死代码；3 个转换内联进 `SM3` 并直接写大端。**SM3 字节级不变**（KAT `66c7f0f4…` 通过） |
| **P3-5/6/7** | 重复 import 核查（已无）、工具类补私有构造、`target/` 清理 | — |
| **DOC** | 除 DOC-10 外的全部 DOC 条目 | 含 `I18nUtils`（**不存在的类**）、`deleteTokenByLoginId` 错名、`AuthUtil.getLoginId()` 描述与代码**相反**、JDK 徽章 8+→17 |

> **P2-7 是本批次唯一的破坏性变更**：若代码依赖 `getToken()` 返回裸值，请改用 `getRawToken()`。

### 2.4 当前基线

```
core 315 例（含 20 个按需跳过的 Redis 契约用例）+ starter 16 例
生产类 57 个；测试源码 39 个（其中 33 个含 @Test，另 6 个是辅助类 / 契约子类）
JDK 17 与 21 均 BUILD SUCCESS，JaCoCo 门槛（LINE 50%）通过
```

---

## 3. 工作方式约定（这个仓库一直在用）

这几条是历次提交反复体现的，接手时建议沿用：

1. **先证缺陷、再动代码**：先写会变红的用例（或探针）证明缺陷真实存在，再修。
2. **反向验证**：改完把修复**变异掉**，确认用例真的会变红。
   ⚠️ **变异前先断言锚点命中数** —— 命中 0 的"验证"是假验证（本项目踩过两次：多行锚点因换行符不匹配、正则被 `bigint(20)` 的右括号截断）。
3. **替身必须保真到会出问题的那一层**：用假仓储验证可达性会得到假结论（P1-12 差点因此误判为"JWT 移除后缺陷已不存在"）。
4. **文档与代码同步收尾**：改完立即更新 `docs/…演进路线.md` 的状态与实施记录、`CHANGELOG.md`。
5. **提交信息**：`<type>(security): 1.5.0版本：<主题>`，`type` 取 `feat`/`fix`/`refactor`/`ci`，破坏性变更在标题末尾标注；正文用 `1) 2) 3)` 分条 + `验证：`/`文档：`/`遗留边界：`。
6. **提交前 `git add -A`**：曾发生过"只提交已跟踪文件、漏掉新增文件导致该提交无法编译"（`0a9dced` → `0c88311` 补交）。

---

## 4. 还没做的（按建议优先级）

完整清单见文档 §4.3 与 §5 的两张表。以下是我认为最值得先看的：

| 项 | 内容 | 状态 | 备注 |
|---|---|---|---|
| **JDBC 并发上限** | 唯一可行且**无需事务**的方案：加 `slot` 列 + `UNIQUE (login_id, slot)`，登录时试 `slot = 1..max`，唯一键冲突即占位失败 | **WONTFIX（暂缓）** | 三个免改表结构方案已实测否决（见文档 §4.3 第 13 行）；因需**破坏性 DDL** 而暂缓。当前 TCK 中以 `supportsAtomicConcurrentLimit()` **显式豁免**，非静默放过 |
| **P1-11 事件机制** | 失败路径监听器异常会顶掉原始异常；`LoginSuccessEvent` 携带完整 token | **DONE（1/3）** | 失败路径隔离已完成（含反向验证）；另两条属公开 API 变更/新特性，留待后续与事件机制一并重做 |
| **P1-13 `SimpleHash`** | 被 README 当作"密码哈希"宣传，实为摘要工具 | **DONE** | 纯文档降级 + 警告块；顺带修掉 DOC-1（示例用的 `MD5Hash`/`Sha256Hash` 是**不存在的类**） |
| **P1-14 `refreshByCredentials`** | 只延长存储层 TTL、不推进 `loginExpireTime`，两套过期口径分叉 | **DONE** | `single` 下 `getSubject` 直接返回 `null`（比"401"更严重）；已按方案 A 口径合一 |
| **TST-6** | 引入 Testcontainers，让 CI 也能跑真实 Redis | `DOING` | 已能本地跑（见 §1）；CI 仍不跑 |
| **`AntPathMatcher` → `PathPattern`** | — | ⏭️ **WONTFIX** | 实测：修不了编码绕过（那是输入源问题）、现有词汇表两者结论一致、中间 `**` 会让存量权限码**直接抛异常**。**不要照着旧条目的"修复方向"去改** |
| ~~阶段 2 · 授权做深~~ | ~~角色继承 + 数据范围 + 权限缓存~~ | ⏭️ **WONTFIX（已改向）** | **超出安全框架职责**：数据范围依赖业务表结构，Spring Security / Shiro 同样不做。**不要照着旧路线图去做数据权限**（见文档 §4.1「方案 B 推翻记录」）。阶段 2 已改为「内核对齐与工程收尾」 |

> **⚠️ 交接必读（`1.5.0` 拍板）**：**不要**去实现数据权限 / 角色继承 / 权限树。判断某能力该不该进框架，用文档 §4.1 末尾的**框架职责边界表**，或问一句「Spring Security 做了吗？」。另外 **SB2 分支（`master`）继续维护**，不做 EOL。

---

## 5. 已知的取舍与"别踩"清单

- **`context-path` 不修**：权限码匹配含 context-path 的完整 URI，改 context-path 会让既有权限码全部失配。已在 README §2.3.3 警告，**刻意不做兜底**（框架替用户猜"带不带前缀"会引入歧义）。
- **`getSubject` 现在返回副本**：依赖"改返回值能持久生效"的代码（仅内存版仓储可能）升级后不再生效。
- **Redis 路径依赖 `EVAL`**：不支持 Lua 的代理（如 Twemproxy）会让登录直接失败。已写入升级检查清单，替代方案是切 `store-type` 到 `single`/`caffeine`。
- **`timeout` 不再支持 `-1`**：需要长会话请配一个较大的正数（如 `86400`）。
- **仓储侧不做 `timeout` 二次校验**：校验只在装配期做一次，仓储信任传入值 —— 这是**有意的信任边界**，不是遗漏。
- **配置项**：`tiny-security.store-type` ∈ `single`(默认)/`caffeine`/`redis`/`jdbc`；`perm-check-mode` ∈ `ANNOTATION`(默认)/`URL`。

---

## 6. 一分钟上手

```bash
git clone https://github.com/llllllxy/tiny-security.git
cd tiny-security && git checkout springboot3
mvn -B clean verify -Dgpg.skip=true          # 期望：BUILD SUCCESS，core 305 / starter 16

# 读这三份，就掌握了全部背景：
#   docs/tiny-security-分析报告与演进路线.md   ← 演进 SSOT（问题清单 + 已完成项 + 实施记录 + 路线图）
#   CHANGELOG.md                              ← 1.5.0 的破坏性变更与升级检查清单
#   docs/tiny-security-开发交接与进度速览.md   ← 本文
```
