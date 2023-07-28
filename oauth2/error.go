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
	ImplementNotFound  CustomError
	InvalidRequest     CustomError
	UnauthorizedClient CustomError
	InvalidAuthHeader  CustomError
	InvalidAuthMessage CustomError
	Unexpected         CustomError
}

var Errors = CustomErrors{
	ImplementNotFound:  CustomError{10000, "未找到实现"},
	InvalidRequest:     CustomError{10001, "无效请求"},
	UnauthorizedClient: CustomError{10002, "未经授权的请求"},
	InvalidAuthHeader:  CustomError{10010, "授权请求头无效"},
	InvalidAuthMessage: CustomError{10011, "授权信息无效"},
	Unexpected:         CustomError{99999, "意料之外的错误"},
}
