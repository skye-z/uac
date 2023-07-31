/*
客户端

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

type Client interface {
	// 客户端编号
	GetId() string
	// 客户端密钥
	GetSecret() string
	// 客户端名称
	GetName() string
	// 客户端主页
	GetHomepage() string
	// 重定向地址
	GetRedirectUri() string
	// 对外公开
	GetPublic() bool
}

type ClientData struct {
	// 客户端编号
	Id string
	// 客户端密钥
	Secret string
	// 客户端名称
	Name string
	// 客户端主页
	Homepage string
	// 重定向地址
	RedirectUri string
	// 是否为公共客户端
	Public bool
}

func (d *ClientData) GetId() string {
	return d.Id
}

func (d *ClientData) GetSecret() string {
	return d.Secret
}

func (d *ClientData) GetName() string {
	return d.Name
}

func (d *ClientData) GetHomepage() string {
	return d.Homepage
}

func (d *ClientData) GetRedirectUri() string {
	return d.RedirectUri
}

func (d *ClientData) GetPublic() bool {
	return d.Public
}

func (d *ClientData) CopyFrom(client ClientData) {
	d.Id = client.GetId()
	d.Secret = client.GetSecret()
	d.Name = client.GetName()
	d.Homepage = client.GetHomepage()
	d.RedirectUri = client.GetRedirectUri()
	d.Public = client.GetPublic()
}

type ClientSecretMatcher interface {
	// 比对客户端密钥
	ClientSecretMatches(secret string) bool
}
