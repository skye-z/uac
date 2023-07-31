# OIDC for UAC

## OIDC 定义

OIDC 即 OpenID Connect, 它是 OAuth2 的完善与补充.

### 协议流程
```
+--------+                                   +--------+
|        |                                   |        |
|        |---------(1) AuthN Request-------->|        |
|        |                                   |        |
|        |  +--------+                       |        |
|        |  |        |                       |        |
|        |  |  End-  |<--(2) AuthN & AuthZ-->|        |
|        |  |  User  |                       |        |
|   RP   |  |        |                       |   OP   |
|        |  +--------+                       |        |
|        |                                   |        |
|        |<--------(3) AuthN Response--------|        |
|        |                                   |        |
|        |---------(4) UserInfo Request----->|        |
|        |                                   |        |
|        |<--------(5) UserInfo Response-----|        |
|        |                                   |        |
+--------+                                   +--------+
```

### 授权码请求内容

| 参数 | 必须 | OAuth2 | 说明 |
| --- | ---- | ------ | --- |
| scope | 是 | 是 | 写死，openid |
| response_type | 是 | 是 | 写死，code |
| client_id | 是 | 是 | RP在OP处注册得到的唯一标识 |
| redirect_uri | 是 | 是 | 用于OP鉴权成功后的回调地址，RP在OP处注册时提供 |
| state | 推荐 | 是 | 请求来回中包含的不透明值，用户防范CSRF攻击 |
| response_mode | 否 | 是 | OP返回数据的模式 |
| nonce | 否 | 否 | 会被放在ID Token的nonce字段，用于防重放攻击 |
| display | 否 | 否 | 定义OP通过什么方式展示用户鉴权界面: page(完整的网页)、popup(弹窗)、touch(触摸设备)、wap |
| prompt | 否 | 否 | 定义OP通过什么方式对用户二次鉴权: none(不进行二次鉴权)、login(重新登录)、consent(获取用户同意使用上次采集到的结果即可)、select_account(选择用户账户) |
| max_age | 否 | 否 | 本次鉴权的有效期。超过该时间后，OP必须对用户再次进行鉴权 |
| ui_locales | 否 | 否 | 用户使用的区域信息 |
| Id_token_hint | 否 | 否 | 忽略 |
| login_hint | 否 | 否 | 忽略 |
| acr_values | 否 | 否 | 忽略 |