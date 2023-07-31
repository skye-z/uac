/*
数据存储

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

// 存储接口
type Store interface {
	// 克隆
	Clone() Store
	// 关闭
	Close()
	// 获取存储服务名称
	GetName() string
	// 使用编号获取客户端对象
	GetClient(id string) (Client, error)
	// 保存授权数据
	SaveAuthorize(*Authorize) error
	// 使用授权码获取授权数据
	GetAuthorize(code string) (*Authorize, error)
	// 使用授权码删除授权数据
	RemoveAuthorize(code string) error
	// 保存访问令牌数据,如果有刷新令牌应同时存入
	SaveAccess(*Access) error
	// 使用访问令牌获取访问数据
	GetAccess(token string) (*Access, error)
	// 使用访问令牌删除访问数据
	RemoveAccess(token string) error
	// 使用刷新令牌获取刷新数据
	GetRefresh(token string) (*Access, error)
	// 使用刷新令牌删除刷新数据
	RemoveRefresh(token string) error
}
