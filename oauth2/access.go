package oauth2

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/pborman/uuid"
)

const (
	AUTHORIZATION_CODE AccessRequestType = "authorization_code"
	REFRESH_TOKEN      AccessRequestType = "refresh_token"
	PASSWORD           AccessRequestType = "password"
	CLIENT_CREDENTIALS AccessRequestType = "client_credentials"
	ASSERTION          AccessRequestType = "assertion"
	IMPLICIT           AccessRequestType = "__implicit"
)

// 访问信息
type Access struct {
	Client    Client
	Authorize *Authorize
	Access    *Access
	// 访问令牌
	AccessToken string
	// 刷新令牌
	RefreshToken string
	// 过期时间
	ExpiresIn int32
	// 请求范围
	Scope string
	// 重定向地址
	RedirectUri string
	// 创建时间
	CreatedAt time.Time
	// 用户信息
	UserData interface{}
}

// 创建访问令牌
type AccessTokenGen interface {
	GenerateAccessToken(data *Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error)
}

// 访问请求类型
type AccessRequestType string

// 请求访问
type AccessRequest struct {
	// 请求访问类型
	Type AccessRequestType
	Code string
	// 客户端
	Client Client
	// 授权信息
	Authorize *Authorize
	// 访问信息
	Access *Access
	// 强制访问
	ForceAccess *Access
	// 重定向地址
	RedirectUri string
	// 授权范围
	Scope string
	// 用户名
	Username string
	// 密码
	Password string
	// 断言类型
	AssertionType string
	// 断言
	Assertion string
	// 是否已授权
	Authorized bool
	// 过期时间
	ExpiresIn int32
	// 是否创建刷新令牌
	GenerateRefresh bool
	// 用户数据
	UserData interface{}
	// 请求对象
	HttpRequest *http.Request
	// 代码验证器
	CodeVerifier string
}

// 创建访问令牌默认实现
type AccessTokenGenDefault struct {
}

func (a *AccessTokenGenDefault) GenerateAccessToken(data *Access, generaterefresh bool) (accesstoken string, refreshtoken string, err error) {
	token := uuid.NewRandom()
	accesstoken = base64.RawURLEncoding.EncodeToString([]byte(token))

	if generaterefresh {
		rtoken := uuid.NewRandom()
		refreshtoken = base64.RawURLEncoding.EncodeToString([]byte(rtoken))
	}
	return
}
