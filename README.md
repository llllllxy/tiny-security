# bluewind-auth-client



## 1、简介

基于token验证的Java Web权限控制框架，支持redis、jdbc和单机session多种存储方式，前后端分离项目、不分离项目均可使用，功能完善、使用简单、易于扩展。


---

## 2、使用

### 2.1、SpringBoot集成

#### 2.1.1、导入
```xml
<dependency>
    <groupId>org.bluewind.authclient</groupId>
    <artifactId>bluewind-auth-client</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

#### 2.1.2、配置

```yaml
authclient:
  # 启用authclient
  enable: true
  # 存储类型，目前支持jdbc和redis和单机内存三种(redis,jdbc,single)
  store-type: redis
  # token名称 (同时也是cookie名称，适配前后端不分离的模式)
  token-name: token
  # token有效期 (即会话时长)，单位秒 默认30分钟(1800秒)
  timeout: 1800
  # token风格，uuid风格 (默认风格)，snowflake (纯数字风格)
  token-style: uuid
  # 当配置为jdbc时，存储token的表名字，默认为b_auth_token
  table-name: b_auth_token
```

> 如果使用jdbcAuthStore需要导入框架提供的sql脚本并且集成好jdbcTemplate；
> 如果使用redisAuthStore，需要集成好redisTemplate

---

### 2.2、登录签发token

```java
@RestController
public class LoginController {
    @Autowired
    private TokenStore tokenStore;
    
    @PostMapping("/token")
    public Map token(String account, String password) {
        // 你的验证逻辑
        // ......
        // 签发token
        Token token = tokenStore.createNewToken(userId, permissions, roles, expire);
        System.out.println("access_token：" + token.getAccessToken());
    }
}
```

createNewToken方法参数说明：

- userId   &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp;   token载体，建议为用户id
- permissions   &emsp;&emsp;&emsp;&emsp;   权限列表
- roles   &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;   角色列表
- expire   &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&nbsp;&nbsp;&nbsp;   token过期时间(单位秒)

> 关于createNewToken方法的详细介绍以及refresh_token机制的用法请在详细文档中查看


---

### 2.3、使用注解或代码限制权限

**1.使用注解的方式：**

```text
// 需要有system权限才能访问
@RequiresPermissions("system")

// 需要有system和front权限才能访问,logical可以不写,默认是AND
@RequiresPermissions(value={"system","front"}, logical=Logical.AND)

// 需要有system或front权限才能访问
@RequiresPermissions(value={"system","front"}, logical=Logical.OR)

// 需要有admin或user角色才能访问
@RequiresRoles(value={"admin","user"}, logical=Logical.OR)
```

> 注解加在Controller的方法或类上面。

<br/>

**2.使用代码的方式：**

```text
//是否有system权限
SubjectUtil.hasPermission(request, "system");

//是否有system或者front权限
SubjectUtil.hasPermission(request, new String[]{"system","front"}, Logical.OR);

//是否有admin或者user角色
SubjectUtil.hasRole(request, new String[]{"admin","user"}, Logical.OR)
```

---

## 2.4、异常处理
bluewind-auth-client在token验证失败和没有权限的时候会抛出自定义异常：

| 自定义异常                  | 描述          | 错误信息                          |
|:----------------------|:-------------|:----------------------------------|
| UnAuthorizedException | 未登录或会话已失效 | 错误信息“未登录或会话已失效！”，错误码401 |
| NoPermissionException | 无权限访问（角色或者资源不匹配）  | 错误信息“无权限访问！”，错误码403   |

建议使用全部异常处理器来捕获异常并进行处理：
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

## 2.5、更多用法

### 2.5.1、使用注解忽略验证
在Controller的方法或类上面添加`@Ignore`注解可排除框架拦截，即表示调用接口不用传递access_token了。


### 2.5.2、自定义查询角色和权限的sql

如果是在签发token的时候指定权限和角色，不重新获取token，不主动更新权限，权限和角色不会实时更新，
可以配置自定义查询角色和权限的sql来实时查询用户的权限和角色：

```text
## 自定义查询用户权限的sql
jwtp.find-permissions-sql=SELECT authority FROM sys_user_authorities WHERE user_id = ?

## 自定义查询用户角色的sql
jwtp.find-roles-sql=SELECT role_id FROM sys_user_role WHERE user_id = ?
```


### 2.5.3、url自动匹配权限
如果不想每个接口都加@RequiresPermissions注解来控制权限，可以配置url自动匹配权限：

```text
## url自动对应权限方式，0 简易模式，1 RESTful模式
jwtp.url-perm-type=0
```

RESTful模式(请求方式:url)：post:/api/login

简易模式(url)：/api/login

> 配置了自动匹配也可以同时使用注解，注解优先级高于自动匹配，你还可以借助Swagger自动扫描所有接口生成权限到数据库权限表中


### 2.5.4、获取当前的用户信息
```text
// 正常可以这样获取
Token token = SubjectUtil.getToken(request);

// 对于排除拦截的接口可以这样获取
Token token = SubjectUtil.parseToken(request);
```   


### 2.5.5、主动让token失效：
```text
// 移除用户的某个token
tokenStore.removeToken(userId, access_token);

// 移除用户的全部token
tokenStore.removeTokensByUserId(userId);
```


### 2.5.6、更新角色和权限列表
修改了用户的角色和权限需要同步更新框架中的角色和权限：
```text
// 更新用户的角色列表
tokenStore.updateRolesByUserId(userId, roles);

// 更新用户的权限列表
tokenStore.updatePermissionsByUserId(userId, permissions);
```

---

## 2.6、前端传递token
放在参数里面用`access_token`传递：
```javascript
$.get("/xxx", { access_token: token }, function(data) {

});
```
放在header里面用`Authorization`、`Bearer`传递：
```javascript
$.ajax({
   url: "/xxx", 
   beforeSend: function(xhr) {
       xhr.setRequestHeader("Authorization", 'Bearer '+ token);
   },
   success: function(data){ }
});
```

---

## 联系方式
前后端分离技术交流群：

![群二维码](https://s2.ax1x.com/2019/07/06/Zw83O1.jpg)

