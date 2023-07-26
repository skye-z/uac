# OAuth2 for UAC

欢迎使用UAC的OAuth2模块, 本模块参照[RFC 6739](https://datatracker.ietf.org/doc/html/rfc6749)标准开发

## OAuth2 定义

以下内容根据[RFC 6739](https://datatracker.ietf.org/doc/html/rfc6749)与本模块具体实现为基础撰写

### 角色

OAuth2中包含4种角色, 分别是:

1. 资源所有者(Resource Owner): 可授予受保护资源访问权限的实体, 若资源所有者是个人, 则可被称为最终用户.
2. 资源服务器(Resource Server): 托管受保护资源的服务器, 可凭访问令牌访问受保护资源.
3. 客户端(Client): 经资源所有者授权访问受保护资源的应用程序.
4. 授权服务器(Authorization Server): 验证资源所有者, 并获取授权后向客户端颁发访问令牌.

### 协议流程

```
 +--------+                    +------------+
 |        |--(1)-- 授权请求 --->|     RO     |
 |        |<-(2)-- 权限授予 ----|  资源所有者  |
 |        |                    +------------+
 |        |                    +------------+
 |  客户端 |--(3)-- 权限授予 --->|     AS     |
 | Client |<-(4)-- 访问令牌 ----|  授权服务器  |
 |        |                    +------------+
 |        |                    +------------+
 |        |--(5)-- 访问令牌 --->|     RS     |
 |        |<-(6)- 受保护资源 ---|  资源服务器  |
 +--------+                    +------------+
```
1. 客户端请求资源所有者给予授权, 最好通过授权服务器作为中介发出;
2. 客户端接收授权信息, 具体见授权类型;
3. 客户端向授权服务器提交授权信息;
4. 授权服务器验证授权信息, 如有效则颁发访问令牌;
5. 客户端向资源服务器出示访问令牌并请求受保护的资源;
6. 资源服务器验证访问令牌, 如有效则为请求提供服务.

> 强烈建议客户端从资源所有者获取授权(步骤1~2)通过授权服务器作为中介.

### 授权模式

授权是资源所有者允许客户端代表其访问受保护资源的凭证, 本模块仅实现4种标准授权类型.

#### 授权码

客户端先申请一个授权码, 然后使用授权码换取令牌.

此模式的授权是最常用最安全的, 它适合带有后端服务的应用程序.

这里也解释了为什么我要在上文建议通过授权服务器作为中介, 因为这样凭据将停留在授权服务器中不会继续传递, 极大程度增强了授权体系的安全性.

#### 隐藏式

这是一种简化的授权码流程, 不再对客户端发出授权码, 而是直接颁发访问令牌.

请注意, 此模式授权服务器不会对客户端进行身份验证, 一般是通过重定向URI来验证客户端身份并将访问令牌传递给客户端, 比较适合纯前端服务.

隐藏式提高了授权效率(减少数据交换)但牺牲了部分安全性, 使用前请权衡再三.

#### 密码式

直接使用资源所有者的用户名与密码作为凭证获取访问令牌.

安全风险极大, 只有在资源所有者和客户端之间高度信任且没有其他授权模式的情况下才可使用, 只建议在内嵌应用中使用, 如操作系统内部.

#### 凭证式

又称客户端凭证, 通过凭证换取访问令牌.

一般用在客户端代表客户端自己时, 即客户端是资源所有者.

此模式非常不安全, 需客户端安全可信.

### 令牌类型

#### 访问令牌

访问令牌(Access Token)是客户端用于访问受保护资源的凭证, 包含了访问范围与有效时间.

#### 刷新令牌

刷新令牌(Refresh Token)是用户获取新的访问令牌的凭证, 用于当前访问令牌失效或要获取额外的令牌时.

下图为令牌刷新流程
```
+--------+                                +----------+
|        |--(1)-------- 权限授予 --------->|          |
|        |<-(2)----- 访问令牌&刷新令牌 ------|          |
|        |                   +----------+ |          |
|        |--(3)-- 访问令牌 -->|          | |           |
| 客户端  |<-(4)- 受保护资源 --|    R S   |  |    A S   |
| Client |--(5)-- 访问令牌 -->| 资源服务器 | | 授权服务器 |
|        |<-(6)-- 令牌失效 ---|          | |           |
|        |                   +----------+ |          |
|        |--(7)-------- 刷新令牌 --------->|           |
|        |<-(8)-- 访问令牌&可选的刷新令牌 ----|          |
+--------+                                +----------+
```
1. 客户端向授权服务器提交授权信息;
2. 授权服务器验证授权信息, 如有效则颁发访问令牌和刷新令牌;
3. 客户端向资源服务器出示访问令牌并请求受保护的资源;
4. 资源服务器验证访问令牌, 如有效则为请求提供服务;
5. 重复步骤(3~4)直到令牌过期,如果客户端已知令牌过期则继续;
6. 由于访问令牌无效, 资源服务器返回错误信息;
7. 客户端向授权服务器出示刷新令牌;
8. 授权服务器验证刷新令牌, 如有效则颁发访问令牌, 此时可选择不颁发刷新令牌.

## 客户端

一个客户端应当包含如下信息:
* 编号(Id): 客户端的标识字符串;
* 名称(Name): 用于可视化展示时显示的客户端名称;
* 主页(Homepage): 用于可视化展示时点击客户端名称跳转的链接;
* 密钥(Secret): 向资源所有者公开, 用于配合编号进行验证客户端;
* 重定向URI(RedirectUri): 可携带验证结果的重定向地址;
* 公共客户端(Public): 即客户端无法保证凭证机密性.

## 开放接口

### 授权接口 `/authorize`

方式: GET/POST

入参
* redirect_uri: 重定向地址
* client_id: 客户端编号
* scope: 请求授权范围
* state: 穿透状态
* response_type: 请求类型(`code`或`token`)
* code_challenge: (仅限`code`类型使用)挑战代码
* code_challenge_method: (仅限`code`类型使用)挑战方法

出参(`code`类型)
* code: 授权码
* state: 穿透状态

### 令牌接口 `/token`

方式: GET/POST (GET需配置启用)

入参
* grant_type: 授权模式
    * authorization_code: 授权码
    * refresh_token: 刷新令牌
    * password: 密码式
    * client_credentials: 凭证式
    * assertion: 断言式
    * __implicit: 隐藏式
* code: 授权码
* code_verifier: (授权码) 挑战算法
    * plain: 不使用(默认)
    * S256: SHA256
* redirect_uri: (授权码) 重定向地址
* refresh_token: 刷新令牌
* username: (密码式) 用户名
* password: (密码式) 密码
* assertion_type: (断言式) 断言类型
* assertion: (断言式) 断言
* scope: (除授权码) 请求授权范围

出参
* access_token: 访问令牌
* refresh_token: 刷新令牌
* expires_in: 有效期限
* token_type: 令牌类型