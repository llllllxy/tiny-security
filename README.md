<h1 align="center">tiny-security</h1>


<p align="center">
	<a target="_blank" href="https://www.apache.org/licenses/LICENSE-2.0">
		<img src="https://img.shields.io/badge/license-Apache%202-green.svg" />
	</a>
	<a target="_blank" href="https://www.oracle.com/technetwork/java/javase/downloads/index.html">
		<img src="https://img.shields.io/badge/JDK-8+-blue.svg" />
	</a>
    <a href="https://github.com/llllllxy/tiny-security/stargazers">
       <img src="https://img.shields.io/github/stars/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/network/members">
        <img src="https://img.shields.io/github/forks/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/watchers">
        <img src="https://img.shields.io/github/watchers/llllllxy/tiny-security?style=flat-square&logo=GitHub">
    </a>
    <a href="https://github.com/llllllxy/tiny-security/issues">
        <img src="https://img.shields.io/github/issues/llllllxy/tiny-security.svg?style=flat-square&logo=GitHub">
    </a>
    <a href='https://gitee.com/leisureLXY/tiny-security'>
        <img src='https://gitee.com/leisureLXY/tiny-security/badge/star.svg?theme=dark' alt='star' />
    </a>
    <br />
</p>

# 1、简介

tiny-security是一个基于SpringBoot开发的轻量级Java Web权限认证框架，支持登录认证、权限认证；同时支持token验证和cookie验证；
支持redis、jdbc和单机session多种会话存储方式（可自行扩展其他存储方式）；前后端分离项目、不分离项目均可使用，功能完善、使用简单，文档清晰，让认证鉴权这件事变得更加简单！

---

# 2、使用

## 2.1、SpringBoot集成

### 2.1.1、引入依赖
```xml
<dependency>
    <groupId>top.lxyccc</groupId>
    <artifactId>tiny-security-boot-starter</artifactId>
    <version>1.2.2</version>
</dependency>
```

> 注： `SpringBoot 3.x` 版本，请将 `tiny-security-boot-starter` 修改为 `tiny-security-boot3-starter` 即可。



### 2.1.2、yml参数配置项

```yaml
tiny-security:
  # 存储类型，目前支持jdbc和redis和单机内存三种(redis,jdbc,single)，如不配置，则默认为single
  store-type: single
  # token名称 (同时也是cookie名称，适配前后端不分离的模式)
  token-name: token
  # token有效期 (即会话时长)，单位秒 默认1800秒(30分钟)
  timeout: 1800
  # credentials凭类型，可配置uuid (默认风格)，snowflake (纯数字风格)，objectid (变种uuid)，random128 (随机128位字符串)，nanoid，ulid
  credentials-style: uuid
  # 当配置为jdbc时，存储token的表名字，默认为t_auth_storage
  table-name: t_auth_storage
  # 权限校验方式，可配置annotation（注解方式）、url（url方式）
  perm-check-mode: annotation
  # jwt密钥
  jwt-secret: K$N)A3*sGGf<wo*22*%&(DF
  # jwt主题
  jwt-subject: tiny-security
```

1. 使用jdbc做存储容器依赖于`jdbcTemplate`，须导入依赖 `spring-boot-starter-jdbc`，在yml里进行数据库连接的相应配置并导入框架提供的sql脚本到数据库中（目前仅提供了MySQL版本）
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
```
2. 使用redis做存储容器依赖于`stringRedisTemplate`，须导入依赖 `spring-boot-starter-data-redis` ，并在yml里进行redis连接的相应配置
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### 2.1.3、配置会话拦截器
 以`SpringBoot2.+`版本为例, 新建配置类`WebMvcConfig.java`，注册会话拦截器，拦截器的拦截路由规则可自行配置
```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Autowired
    private AuthenticeInterceptor authenticeInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        
        // 注册会话拦截器
        registry.addInterceptor(authenticeInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/login");
    }
}
```

### 2.1.4、配置权限角色拦截器（可选）
以`SpringBoot2.+`版本为例, 在配置类`WebMvcConfig.java`内，注册权限角色拦截器，拦截器的拦截路由规则可自行配置
```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    // 按需要来，如果不需要角色权限控制，可以不配置此拦截器
    @Autowired
    private PermissionInterceptor permissionInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {

        // 注册权限拦截器
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/login");
    }
}
```

使用权限角色拦截器，还需要实现`PermissionInfoInterface`接口，提供权限和角色编码列表获取的业务逻辑（框架没有对权限和角色标记码进行缓存，如需缓存请自行处理），例如以下代码：
```java
@Component
public class PermissionInfoInterfaceImpl implements PermissionInfoInterface {
    private final static Logger logger = LoggerFactory.getLogger(PermissionInfoInterfaceImpl.class);


    /**
     * 返回一个账号所拥有的权限码集合
     * @param loginId，账号id，即你在调用 authProvider.login(id) 时写入的标识值。
     */
    @Override
    public Set<String> getPermissionSet(Object loginId) {
        if (logger.isInfoEnabled()) {
            logger.info("PermissionInfoInterfaceImpl -- getPermissionSet -- loginId = {}", loginId);
        }
        // 自定义权限编码列表获取逻辑，下面的只是示例
        Set<String> permissionSet = new HashSet<String>() {{
            add("权限1");
            add("权限2");
        }};

        return permissionSet;
    }

    /**
     * 返回一个账号所拥有的角色标识集合 (权限与角色可分开校验)
     * @param loginId，账号id，即你在调用 authProvider.login(id) 时写入的标识值。
     */
    @Override
    public Set<String> getRoleSet(Object loginId) {
        if (logger.isInfoEnabled()) {
            logger.info("PermissionInfoInterfaceImpl -- getRoleSet -- loginId = {}", loginId);
        }
        // 自定义角色编码列表获取逻辑，下面的只是示例
        Set<String> roleSet = new HashSet<String>() {{
            add("角色1");
            add("角色2");
        }};
        return roleSet;
    }
}
```

---

## 2.2 会话认证

### 2.2.1、登录签发token，创建会话

```java
@Controller
public class IndexController {
    final static Logger logger = LoggerFactory.getLogger(IndexController.class);
    
    @Autowired
    private AuthProvider authProvider;

    @ResponseBody
    @PostMapping("/login")
    public Result<Object> login(@RequestParam("username") String username,
                                @RequestParam("password") String password) {
        // 你的登录验证逻辑
        // ......
        // 签发token
        String token = authProvider.login(username);
        return Result.ok("登录成功！", token);
    }
}
```
login方法参数说明：
- loginId  登录的账号id，建议的数据类型：long | int | String，建议为用户id，不可以传入复杂类型，如：User、Admin 等等

---

### 2.2.2、退出登录，注销会话

```java
@Controller
public class IndexController {
    final static Logger logger = LoggerFactory.getLogger(IndexController.class);
   
    @Autowired
    private AuthProvider authProvider;

    @ResponseBody
    @GetMapping("/logout")
    public Result<Object> logout(HttpServletRequest request) {
        // 退出登录，注销会话
        authProvider.logout(request);
        
        // 不传入request亦可，会自动获取当前的request
        // authProvider.logout();

        return Result.ok("退出登录成功！");
    }
}
```

### 2.2.3、获取当前登录会话
```java
// 注入authProvider
@Autowired
private AuthProvider authProvider;

// 获取当前登录会话id
Object loginId = authProvider.getLoginId();
或者直接调用静态方法
Object loginId = AuthUtil.getLoginId()

// 获取当前登录会话信息
LoginSubject LoginSubject = authProvider.getLoginSubject();
或者直接调用静态方法
LoginSubject LoginSubject = AuthUtil.getLoginSubject();
```

---

### 2.2.4、获取当前登录用户token
```java
// 注入authProvider
@Autowired
private AuthProvider authProvider;

authProvider.getToken();
或者
authProvider.getToken(HttpServletRequest request);
```
---

### 2.2.5、获取当前登录用户凭证（对应redis或database里的唯一键）
```java
// 注入authProvider
@Autowired
private AuthProvider authProvider;

authProvider.getCredentials();
或者
authProvider.getCredentials(HttpServletRequest request);
```

---

### 2.2.6、使用会话验证忽略注解 `@Ignore`
在Controller的方法或类上面添加`@Ignore`注解可排除框架会话拦截，即表示调用接口不用传递token了。

---

### 2.2.7、会话主动注销
```java
// 注入authProvider
@Autowired
private AuthProvider authProvider;

// 根据token，使会话注销
authProvider.deleteByToken(token);

// 根据会话凭证credentials，使会话注销
authProvider.deleteByCredentials(credentials);

// 根据用户loginId，使该用户的全部会话都注销
authProvider.deleteTokenByLoginId(loginId);

```

---


## 2.3、权限认证

### 2.3.1、注解方式控制权限

**1.注解解释：**

```java
// 需要有 system:user:add 权限才能访问
@RequiresPermissions("system:user:add")

// 需要有 system:user:add 和 system:user:delete 权限才能访问, logical可以不写,默认是AND
@RequiresPermissions(value={"system:user:add", "system:user:delete"}, logical=Logical.AND)

// 需要有 system:user:add 或 system:user:delete 权限才能访问
@RequiresPermissions(value={"system:user:add", "system:user:delete"}, logical=Logical.OR)

// 需要有user角色才能访问
@RequiresRoles(value="user")

// 需要有admin和user角色才能访问
@RequiresRoles(value={"admin", "user"}, logical=Logical.AND)

// 需要有admin或user角色才能访问
@RequiresRoles(value={"admin", "user"}, logical=Logical.OR)
```

> 注解加在Controller的方法或类上面

**2.代码示例：**

```java
@Controller
public class IndexController {
    final static Logger logger = LoggerFactory.getLogger(IndexController.class);
    
    @Autowired
    private AuthProvider authProvider;

    @RequiresPermissions("权限3")
    @ResponseBody
    @GetMapping("/testPermission")
    public Result<Object> testPermission() {
        return Result.ok("testPermission测试成功！");
    }

    @RequiresRoles(value="角色1")
    @ResponseBody
    @GetMapping("/testRole")
    public Result<Object> testRole() {
        logger.info("LoginSubject = {}", authProvider.getLoginSubject());
        logger.info("authProvider.getLoginId() = {}", authProvider.getLoginId());
        logger.info("AuthUtil.getLoginId() = {}", AuthUtil.getLoginId());
        logger.info("token = {}", authProvider.getToken());
        return Result.ok("testRole测试成功！", authProvider.getLoginId());
    }
}
```

---

### 2.3.2、代码方式控制权限
**1.代码示例：** 

```java

// 判断：当前账号是否含有指定角色, 返回 true 或 false
AuthUtil.hasRole("role1");

// 判断：当前账号是否含有指定角色 [指定多个，必须全部验证通过]
AuthUtil.hasAllRole("role1", "role2");

// 判断：当前账号是否含有指定角色 [指定多个，只要其一验证通过即可]
AuthUtil.hasAnyRole("role1", "role2");

// 判断：当前账号是否含有指定权限, 返回 true 或 false
AuthUtil.hasPermission("permission1");

// 判断：当前账号是否含有指定权限 [指定多个，必须全部验证通过]
AuthUtil.hasAllPermission("permission1", "permission2");

// 判断：当前账号是否含有指定权限 [指定多个，只要其一验证通过即可]
AuthUtil.hasAnyPermission("permission1", "permission2");

```

---

### 2.3.3、权限通配符的使用
> 🚨支持使用通配符指定泛权限，例如当一个账号拥有system:user:*的权限时，system:user:add、system:user:delete、system:user:update都将匹配通过

> ⚠️注意
> 当一个账号拥有 "*" 权限时，可以验证通过任何权限码 （角色认证同理）, 所以请谨慎使用 "*" 权限码

---

## 2.4、异常处理
tiny-security在会话验证失败和权限验证失败的会抛出自定义异常：

| 自定义异常                  | 描述          | 错误信息                          |
|:----------------------|:-------------|:----------------------------------|
| UnAuthorizedException | 未登录或会话已失效 | 错误信息“未登录或会话已失效！”，错误码401 |
| NoPermissionException | 无权限访问（角色或者资源不匹配）  | 错误信息“无权限访问！”，错误码403   |

需要使用全局异常处理器来捕获异常并进行处理返回JSON数据（或者页面）：

```java
@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // 捕捉运行时异常
    @ResponseBody
    @ExceptionHandler(RuntimeException.class)
    public Result<Object> handleRuntimeException(Exception e) {
        logger.error("GlobalExceptionHandler -- RuntimeException = {e}", e);
        return Result.create(HttpStatus.ERROR, e.getMessage());
    }

    // 缺少权限异常
    @ResponseBody
    @ExceptionHandler(value = NoPermissionException.class)
    public Result<Object> handleAuthorizationException() {
        return Result.create(HttpStatus.FORBIDDEN, "接口无权限，请联系系统管理员", null);
    }
    
    // 未登陆异常
    @ResponseBody
    @ExceptionHandler(value = UnAuthorizedException.class)
    public Result<Object> handleAuthenticationException() {
        return Result.create(HttpStatus.UNAUTHORIZED, "会话已失效，请重新登录", null);
    }
}
```

---

## 2.5、其他更多用法

### 2.5.1、前端传递token
1. 放在参数里面用`token`传递：
```javascript
$.get("/xxx", { "token": token }, function(data) {

});
```
2. 放在header里面用`token`传递：
```javascript
$.ajax({
   url: "/xxx", 
   beforeSend: function(xhr) {
       xhr.setRequestHeader("token", token);
   },
   success: function(data){ }
});
```
3. 前后端不分离的项目会自动从cookie里获取`token`

---

### 2.5.2、自定义AuthProvider
框架内置了JdbcAuthProvider、RedisAuthProvider和SingleAuthProvider三种会话实现，
如果仍然无法满足你的需求，或者你想存在其他什么地方，比如存在磁盘文件、MongoDB中，只需以下三步即可：
- 继承org.tinycloud.security.provider.AbstractAuthProvider抽象类， 实现里面的抽象方法，
- 注入bean，如下
```java
   @Component
   public class MongoAuthProvider extends AbstractAuthProvider {
        // ...
   }
```
- 删除store-type的配置


### 2.5.3、密码加密算法
框架封装了一些常见的加密算法，可供使用
1. 摘要算法：
支持MD5、SHA256和国密SM3算法
```java
    new MD5Hash("123456", "323@#@$1234da", 1).toHex();
    new MD5Hash("123456", "323@#@$1234da").toHex();
    new MD5Hash("123456").toHex();
    new MD5Hash("123456", "323@#@$1234da", 2).toHex();
    new MD5Hash("123456", "323@#@$1234da", 3).toHex();
    new MD5Hash("123456", "323@#@$1234da", 3).toBase64();
    
    new Sha256Hash("123456", "323@#@$1234da", 10).toBase64();
    new Sha256Hash("123456", "323@#@$1234da").toHex();
    new Sha256Hash("123456").toHex();
    new Sha256Hash("123456", "323@#@$1234da", 2).toHex();
    new Sha256Hash("123456", "323@#@$1234da", 3).toHex();
    new Sha256Hash("123456", "323@#@$1234da", 3).toBase64();

    new SM3Hash("123456", "323@#@$1234da", 1).toHex();
    new SM3Hash("123456", "323@#@$1234da").toHex();
    new SM3Hash("123456").toHex();
    new SM3Hash("123456", "323@#@$1234da", 2).toHex();
    new SM3Hash("123456", "323@#@$1234da", 4).toHex();
    new SM3Hash("123456", "323@#@$1234da").toBase64();
```

2. 对称加密
支持AES256-CBC算法
```java
    // 原文:
    String message = "Helloworld!";
    System.out.println("Message: " + message);

    // 使用方法（密钥长度需要为32字节，iv长度需要为16字节）
    AESUtil aesUtils = AESUtil.builder().secretKey("1G78Av#yej%WZJ3uiSZRz9oy%UAv4AAA").ivParameter("E%BAAAUTvXfwSuGQ").build();

    // 加密:
    String encrypted = aesUtils.encrypt(message);
    System.out.println("加密: " + encrypted);

    // 解密:
    String decrypted = aesUtils.decrypt(encrypted);
    System.out.println("解密: " + decrypted);
```

3. 非对称加密
支持RSA2048加密
```java
    Map<String, String> pair = generateKeyPair();
    String publicKey = pair.get("publicKey");
    String privateKey = pair.get("privateKey");

    // 使用公钥加密
    String encryptedValue = encryptByPublicKey(publicKey, "abcdefg");
    System.out.println(encryptedValue);

    // 使用私钥解密
    String decryptedValue = decryptByPrivateKey(privateKey, encryptedValue);
    System.out.println(decryptedValue);
```