/*
错误处理

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

import (
	"errors"
	"fmt"
)

type CustomError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *CustomError) Error() string {
	return fmt.Sprintf("message: %s, code: %d", e.Message, e.Code)
}

func (e *CustomError) Throw() error {
	return errors.New(fmt.Sprint(e.Code))
}

type CustomErrors struct {
	// 未找到实现
	ImplementNotFound CustomError
	// 无效请求
	InvalidRequest CustomError
	// 未经授权的客户端
	UnauthorizedClient CustomError
	// 授权请求头无效
	InvalidAuthHeader CustomError
	// 授权信息无效
	InvalidAuthMessage CustomError
	// 授权请求类型无效
	InvalidAuthRequestType CustomError
	// 重定向地址无效
	InvalidRedirectUri CustomError
	// 地址方案无效
	InvalidUriScheme CustomError
	// 地址主机无效
	InvalidUriHosts CustomError

	// 拒绝访问
	DeniedAccess CustomError
	// URI中禁止出现次级资源
	ProhibitFragment CustomError
	// 意料之外的错误
	Unexpected CustomError
}

var Errors = CustomErrors{
	ImplementNotFound:      CustomError{10000, "未找到实现"},
	InvalidRequest:         CustomError{10001, "无效请求"},
	UnauthorizedClient:     CustomError{10002, "未经授权的客户端"},
	InvalidAuthHeader:      CustomError{10010, "授权请求头无效"},
	InvalidAuthMessage:     CustomError{10011, "授权信息无效"},
	InvalidAuthRequestType: CustomError{10012, "授权请求类型无效"},
	InvalidRedirectUri:     CustomError{10013, "重定向地址无效"},
	InvalidUriScheme:       CustomError{10013, "地址方案无效"},
	InvalidUriHosts:        CustomError{10013, "地址主机无效"},
	DeniedAccess:           CustomError{10014, "拒绝访问"},
	ProhibitFragment:       CustomError{10015, "URI中禁止出现次级资源"},
	Unexpected:             CustomError{99999, "意料之外的错误"},
}
