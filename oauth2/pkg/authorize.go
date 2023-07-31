/*
授权信息

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package pkg

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/pborman/uuid"
)

const (
	CODE  AuthorizeRequestType = "code"
	TOKEN AuthorizeRequestType = "token"

	PKCE_PLAIN string = "plain"
	PKCE_S256  string = "S256"
)

// 请求授权类型
type AuthorizeRequestType string

// 请求授权
type AuthorizeRequest struct {
	// 请求授权类型
	Type AuthorizeRequestType
	// 客户端
	Client Client
	// 过期时间
	ExpiresIn int32
	// 请求范围
	Scope string
	// 重定向地址
	RedirectUri string
	// 状态
	State string
	// 用户信息
	UserData interface{}
	// 挑战代码
	CodeChallenge string
	// 挑战方法
	CodeChallengeMethod string

	// 请求是否被授权
	Authorized bool
	// 请求对象
	HttpRequest *http.Request
}

// 授权信息
type Authorize struct {
	// 客户端
	Client Client
	// 授权码
	Code string
	// 过期时间
	ExpiresIn int32
	// 请求范围
	Scope string
	// 重定向地址
	RedirectUri string
	// 状态
	State string
	// 创建时间
	CreatedAt time.Time
	// 用户信息
	UserData interface{}
	// 挑战代码
	CodeChallenge string
	// 挑战方法
	CodeChallengeMethod string
}

// 授权是否已过期
func (d *Authorize) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// 指定时间时是否已过期
func (d *Authorize) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// 获取过期时间
func (d *Authorize) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// 创建授权令牌
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *Authorize) (string, error)
}

// 创建授权令牌默认实现
type AuthorizeTokenGenDefault struct {
}

func (a *AuthorizeTokenGenDefault) GenerateAuthorizeToken(data *Authorize) (ret string, err error) {
	token := uuid.NewRandom()
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}
