/*
工具

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// 检查客户端密钥
func CheckClientSecret(client Client, secret string) bool {
	switch client := client.(type) {
	// 实现了客户端密钥比对接口
	case ClientSecretMatcher:
		return client.ClientSecretMatches(secret)
	default:
		// 没有实现则明文校验
		return subtle.ConstantTimeCompare([]byte(client.GetSecret()), []byte(secret)) == 1
	}
}

// 获取第一个URI
func GetFirstUri(baseUriList string) string {
	slist := strings.Split(baseUriList, ",")
	if len(slist) > 0 {
		return slist[0]
	}
	return ""
}

// 校验URI列表
func ValidateUriList(baseUriList string, redirectUri string, allow bool) (realRedirectUri string, err error) {
	// 创建列表切片
	var slist []string
	if allow {
		slist = strings.Split(baseUriList, ",")
	} else {
		slist = make([]string, 0)
		slist = append(slist, baseUriList)
	}
	// 遍历列表
	for _, sitem := range slist {
		realRedirectUri, err = ValidateUri(sitem, redirectUri)
		// 通过验证且为报错
		if err == nil {
			return realRedirectUri, nil
		}
	}

	return "", Errors.InvalidRedirectUri.Throw()
}

// 验证URI
func ValidateUri(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	// 传入为空
	if baseUri == "" || redirectUri == "" {
		return "", errors.New("urls cannot be blank")
	}
	// 分析URL
	base, redirect, err := AnalysisUrls(baseUri, redirectUri)
	if err != nil {
		return "", err
	}
	// 精准路径匹配
	if base.Path == redirect.Path {
		return redirect.String(), nil
	}
	// 前缀地址匹配
	requiredPrefix := strings.TrimRight(base.Path, "/") + "/"
	if !strings.HasPrefix(redirect.Path, requiredPrefix) {
		return "", Errors.InvalidRedirectUri.Throw()
	}
	return redirect.String(), nil
}

// 分析URL
func AnalysisUrls(baseUrl, redirectUrl string) (retBaseUrl, retRedirectUrl *url.URL, err error) {
	var base, redirect *url.URL
	// 分析URL
	if base, err = url.Parse(baseUrl); err != nil {
		return nil, nil, err
	}
	if redirect, err = url.Parse(redirectUrl); err != nil {
		return nil, nil, err
	}
	// 出现次级资源(http://xxxx/xx#次级资源)
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, Errors.ProhibitFragment.Throw()
	}
	// 方案不匹配
	if redirect.Scheme != base.Scheme {
		return nil, nil, Errors.InvalidUriScheme.Throw()
	}

	var (
		redirectMatch bool
		host          string
	)

	// 验证主机地址
	if redirect.Host == base.Host {
		redirectMatch = true
		host = base.Host
	} else if baseIP := net.ParseIP(base.Host); baseIP != nil && baseIP.IsLoopback() && base.Scheme == "http" {
		// 回环地址砍掉端口
		if redirectIP := net.ParseIP(redirect.Hostname()); redirectIP != nil && redirectIP.IsLoopback() {
			redirectMatch = true
			host = redirect.Host
		}
	}
	// 主机不匹配
	if !redirectMatch {
		return nil, nil, Errors.InvalidUriHosts.Throw()
	}

	// 返回解析数据
	retBaseUrl = (&url.URL{Scheme: base.Scheme, Host: host}).ResolveReference(&url.URL{Path: base.Path})
	retRedirectUrl = (&url.URL{Scheme: base.Scheme, Host: host}).ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})
	return retBaseUrl, retRedirectUrl, nil
}

// 输出JSON
func OutputJSON(res *Response, resWriter http.ResponseWriter) error {
	// 添加响应头
	for i, k := range res.Headers {
		for _, v := range k {
			resWriter.Header().Add(i, v)
		}
	}
	// 判断是否重定向
	if res.Type == REDIRECT {
		url, err := res.GetRedirectUrl()
		if err != nil {
			return err
		}
		// 设置302重定向
		resWriter.Header().Add("Location", url)
		resWriter.WriteHeader(302)
	} else {
		// 设置JSON内容格式
		if resWriter.Header().Get("Content-Type") == "" {
			resWriter.Header().Set("Content-Type", "application/json")
		}
		// 输出状态码
		resWriter.WriteHeader(res.HttpCode)
		// 输出JSON
		encoder := json.NewEncoder(resWriter)
		err := encoder.Encode(res.Output)
		if err != nil {
			return err
		}
	}
	return nil
}
