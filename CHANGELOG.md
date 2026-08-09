# tiny-security 升级日志（CHANGELOG）

> 分支：`springboot3`（Spring Boot 3.x / JDK 17+）
> 数据来源：基于 `springboot3` 分支 first-parent 主线，按版本发布提交逐段切分
> 版本区间：`1.2.0`（2025-05-14）→ `1.3.1`（2026-08-09）
> 更早基线：`1.1.0 全新版本发布`（2024-09-06，springboot3 重生起点）

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
