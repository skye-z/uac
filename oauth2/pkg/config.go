/*
服务配置

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package pkg

// 允许的授权请求类型
type AllowedAuthorizeType []AuthorizeRequestType

// 允许的访问请求类型
type AllowedAccessType []AccessRequestType

// 判断是否允许传入的授权请求类型
func (t AllowedAuthorizeType) Allow(rt AuthorizeRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// 判断是否允许传入的访问请求类型
func (t AllowedAccessType) Allow(rt AccessRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// 服务配置
type Config struct {
	// 授权令牌过期时间(秒),默认3分钟
	AuthorizationExpiration int32
	// 访问令牌过期时间(秒),默认1小时
	AccessExpiration int32
	// 令牌类型
	TokenType string
	// 允许的授权请求类型
	AllowedAuthorizeTypes AllowedAuthorizeType
	// 允许的访问请求类型
	AllowedAccessTypes AllowedAccessType
	// 错误状态码
	ErrorStatusCode int
	// 允许在params中发送密钥
	AllowClientSecretInParams bool
	// 允许Get请求
	AllowGetAccessRequest bool
	// 允许多个重定向地址,使用逗号分割
	AllowMultipleRedirectUri bool
	// 允许刷新令牌
	AllowRetainToken bool
	// 要求请求使用PKCE
	RequirePKCEForPublicClients bool
}

func NewServerConfig() *Config {
	return &Config{
		AuthorizationExpiration:   180,
		AccessExpiration:          3600,
		TokenType:                 "Bearer",
		AllowedAuthorizeTypes:     AllowedAuthorizeType{CODE},
		AllowedAccessTypes:        AllowedAccessType{AUTHORIZATION_CODE},
		ErrorStatusCode:           200,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
		AllowRetainToken:          false,
	}
}
