/*
请求授权

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package pkg

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

// 请求头 Basic Auth 验证信息
type BasicAuth struct {
	Username string
	Password string
}

// 获取请求头中的授权信息
func getAuthorization(req *http.Request) string {
	return req.Header.Get("Authorization")
}

// 从请求中获取 Basic 验证信息
// Refer https://datatracker.ietf.org/doc/html/rfc6749#autoid-19
func GetBasicAuth(req *http.Request) (*BasicAuth, error) {
	// 获取请求头中的授权信息
	auth := getAuthorization(req)
	if auth == "" {
		return nil, nil
	}
	// 分割授权信息前缀
	param := strings.SplitN(auth, " ", 2)
	if len(param) != 2 || param[0] != "Basic" {
		return nil, Errors.InvalidAuthHeader.Throw()
	}
	// 解码授权信息主体
	code, err := base64.StdEncoding.DecodeString(param[1])
	if err != nil {
		return nil, err
	}
	// 分割授权客户端与密钥
	param = strings.SplitN(string(code), ":", 2)
	if len(param) != 2 {
		return nil, Errors.InvalidAuthMessage.Throw()
	}
	// 提取客户端标识
	clientId, err := url.QueryUnescape(param[0])
	if err != nil {
		return nil, err
	}
	// 提取客户端密钥
	clientSecret, err := url.QueryUnescape(param[1])
	if err != nil {
		return nil, err
	}
	// 返回授权信息
	return &BasicAuth{Username: clientId, Password: clientSecret}, nil
}
