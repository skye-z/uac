/*
日志处理

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package pkg

import "log"

// 日志记录器接口
type Logger interface {
	// 格式化输出
	Printf(format string, v ...interface{})
}

// 控制台日志记录器
type LoggerConsole struct{}

// 输出到控制台
func (lc LoggerConsole) Printf(format string, v ...interface{}) {
	log.Printf("[OAuth2] "+format, v...)
}
