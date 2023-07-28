package oauth2

import (
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
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

// 授权请求处理
func (s *Server) HandleAuthorizeRequest(res *Response, req *http.Request) *AuthorizeRequest {
	req.ParseForm()

	// 获取重定向地址
	redirectUri, err := url.QueryUnescape(req.FormValue("redirect_uri"))
	if err != nil {
		res.SetErrorState(Errors.InvalidRequest.Message, "", "")
		res.InternalError = err
		return nil
	}

	// 创建授权请求
	ret := &AuthorizeRequest{
		State:       req.FormValue("state"),
		Scope:       req.FormValue("scope"),
		RedirectUri: redirectUri,
		Authorized:  false,
		HttpRequest: req,
	}

	// 获取客户端信息
	ret.Client, err = res.Store.GetClient(req.FormValue("client_id"))
	// 客户端接口未实现
	if err == Errors.ImplementNotFound.Throw() {
		res.SetErrorState(Errors.ImplementNotFound.Message, "", ret.State)
		return nil
	}
	// 客户端获取出错
	if err != nil {
		res.SetErrorState(Errors.Unexpected.Message, "", ret.State)
		res.InternalError = err
		return nil
	}
	// 未获取到客户端
	if ret.Client == nil {
		res.SetErrorState(Errors.UnauthorizedClient.Message, "", ret.State)
		return nil
	}
	// 未获取到重定向地址(必须要有)
	if ret.Client.GetRedirectUri() == "" {
		res.SetErrorState(Errors.UnauthorizedClient.Message, "", ret.State)
		return nil
	}
	// 允许多个重定向地址
	if ret.RedirectUri != "" && s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = GetFirstUri(ret.Client.GetRedirectUri())
	}
	// 校验重定向地址是否匹配
	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.AllowMultipleRedirectUri); err != nil {
		res.SetErrorState(Errors.InvalidRequest.Message, "", ret.State)
		res.InternalError = err
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}
	// 设置重定向地址
	res.SetRedirect(ret.RedirectUri)
	// 获取请求类型
	requestType := AuthorizeRequestType(req.FormValue("response_type"))
	// 检查请求类型是否在允许范围
	if s.Config.AllowedAuthorizeTypes.Allow(requestType) {
		switch requestType {
		case CODE:
			ret.Type = CODE
			ret.ExpiresIn = s.Config.AuthorizationExpiration
			// 判断挑战代码是否为空
			if codeChallenge := req.FormValue("code_challenge"); len(codeChallenge) == 0 {
				// 判断是否要求请求使用PKCE挑战
				// https://datatracker.ietf.org/doc/html/rfc7636
				if s.Config.RequirePKCEForPublicClients && CheckClientSecret(ret.Client, "") {
					res.SetErrorState(Errors.InvalidRequest.Message, "code_challenge (rfc7636) required for public clients", ret.State)
					return nil
				}
			} else {
				// 获取挑战方法
				codeChallengeMethod := req.FormValue("code_challenge_method")
				// 未传入则默认 plain
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = PKCE_PLAIN
				}
				// 判断挑战方法是否在允许范围
				if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
					res.SetErrorState(Errors.InvalidRequest.Message, "code_challenge_method transform algorithm not supported (rfc7636)", ret.State)
					return nil
				}
				// 判断挑战代码是否包含非法字符
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					res.SetErrorState(Errors.InvalidRequest.Message, "code_challenge invalid (rfc7636)", ret.State)
					return nil
				}
				ret.CodeChallenge = codeChallenge
				ret.CodeChallengeMethod = codeChallengeMethod
			}
		case TOKEN:
			ret.Type = TOKEN
			ret.ExpiresIn = s.Config.AccessExpiration
		}
		return ret
	}
	res.SetErrorState(Errors.InvalidAuthRequestType.Message, "", ret.State)
	return nil
}

// 授权请求完成
func (s *Server) FinishAuthorizeRequest(res *Response, req *http.Request, ar *AuthorizeRequest) {
	// 处理出错时直接返回
	if res.IsError {
		return
	}
	// 设置重定向地址
	res.SetRedirect(ar.RedirectUri)
	// 判断是否已授权
	if ar.Authorized {
		// 授权请求类型是否为令牌
		if ar.Type == TOKEN {
			res.SetRedirectFragment(true)
			// 请求创建访问令牌,此时不应生成刷新令牌
			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				GenerateRefresh: false,
				Authorized:      true,
				ExpiresIn:       ar.ExpiresIn,
				UserData:        ar.UserData,
			}
			// 完成访问令牌请求
			s.FinishAccessRequest(res, req, ret)
			// 判断状态
			if ar.State != "" && res.InternalError == nil {
				res.Output["state"] = ar.State
			}
		} else {
			// 创建授权令牌对象
			ret := &Authorize{
				Client:              ar.Client,
				CreatedAt:           s.Now(),
				ExpiresIn:           ar.ExpiresIn,
				RedirectUri:         ar.RedirectUri,
				State:               ar.State,
				Scope:               ar.Scope,
				UserData:            ar.UserData,
				CodeChallenge:       ar.CodeChallenge,
				CodeChallengeMethod: ar.CodeChallengeMethod,
			}
			// 授权令牌,获取授权码
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				res.SetErrorState(Errors.Unexpected.Message, "", ar.State)
				res.InternalError = err
				return
			}
			ret.Code = code
			// 保存授权码
			if err = res.Store.SaveAuthorize(ret); err != nil {
				res.SetErrorState(Errors.Unexpected.Message, "", ar.State)
				res.InternalError = err
				return
			}
			// 返回授权码和穿透状态
			res.Output["code"] = ret.Code
			res.Output["state"] = ret.State
		}
	} else {
		res.SetErrorState(Errors.DeniedAccess.Message, "", ar.State)
	}
}
