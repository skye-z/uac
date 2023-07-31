/*
HTTP响应

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// 响应数据
type ResponseData map[string]interface{}

// 响应类型
type ResponseType int

const (
	DATA ResponseType = iota
	REDIRECT
)

// 请求
type Response struct {
	// 响应类型
	Type ResponseType
	// HTTP状态码
	HttpCode int
	// 错误码
	Code int
	// 消息
	Message string
	// 处理状态
	State bool
	Store Store
	// 地址
	URL string
	// 输出数据
	Output ResponseData
	// 响应头
	Headers http.Header
	// 网络错误
	InternalError error
	// 重定向到次级资源
	RedirectInFragment bool
}

// 创建默认响应
func NewResponse(store Store) *Response {
	r := &Response{
		Type:     DATA,
		HttpCode: 200,
		Output:   make(ResponseData),
		Headers:  make(http.Header),
		State:    true,
		Store:    store.Clone(),
	}
	r.Headers.Add(
		"Cache-Control",
		"no-cache, no-store, max-age=0, must-revalidate",
	)
	r.Headers.Add("Pragma", "no-cache")
	r.Headers.Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
	return r
}

// 输出错误信息
func (r *Response) OutError(obj CustomError) {
	r.OutErrorUri(obj, "")
}

// 输出错误状态
func (r *Response) OutErrorState(obj CustomError, state string) {
	r.OutErrorUri(obj, state)
}

// 输出错误URI
func (r *Response) OutErrorUri(obj CustomError, state string) {
	r.State = false
	r.Code = obj.Code
	r.Message = obj.Message

	r.Output = make(ResponseData)
	r.Output["error"] = r.Code
	r.Output["error_description"] = r.Message
	if state != "" {
		r.Output["state"] = state
	}
}

// 设置重定向
func (r *Response) SetRedirect(url string) {
	r.Type = REDIRECT
	r.URL = url
}

// 设置次级资源重定向
func (r *Response) SetRedirectFragment(f bool) {
	r.RedirectInFragment = f
}

// 获取重定向地址
func (r *Response) GetRedirectUrl() (string, error) {
	if r.Type != REDIRECT {
		return "", errors.New("not a redirect response")
	}

	u, err := url.Parse(r.URL)
	if err != nil {
		return "", err
	}

	var q url.Values
	if r.RedirectInFragment {
		q = url.Values{}
	} else {
		q = u.Query()
	}

	for n, v := range r.Output {
		q.Set(n, fmt.Sprint(v))
	}

	if r.RedirectInFragment {
		u.Fragment = ""
		redirectURI := u.String() + "#" + q.Encode()
		return redirectURI, nil
	}

	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func (r *Response) Close() {
	r.Store.Close()
}
