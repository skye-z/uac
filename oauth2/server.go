/*
服务器

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/skye-z/uac/oauth2/pkg"
)

var (
	pkceMatcher = regexp.MustCompile("^[a-zA-Z0-9~._-]{43,128}$")
)

type Server struct {
	Config            *Config
	Store             pkg.Store
	AuthorizeTokenGen pkg.AuthorizeTokenGen
	AccessTokenGen    pkg.AccessTokenGen
	Now               func() time.Time
	Logger            pkg.Logger
}

// 创建服务器
func NewServer(config *Config, store pkg.Store) *Server {
	logger := &pkg.LoggerConsole{}
	logger.Printf("Create server")
	logger.Printf("Loading %s storage", store.GetName())
	return &Server{
		Config:            config,
		Store:             store,
		AuthorizeTokenGen: &pkg.AuthorizeTokenGenDefault{},
		AccessTokenGen:    &pkg.AccessTokenGenDefault{},
		Now:               time.Now,
		Logger:            logger,
	}
}

// 创建响应
func (s *Server) NewResponse() *pkg.Response {
	r := pkg.NewResponse(s.Store)
	r.Code = s.Config.ErrorStatusCode
	return r
}

// 授权请求处理
func (s *Server) HandleAuthorizeRequest(res *pkg.Response, req *http.Request) *pkg.AuthorizeRequest {
	req.ParseForm()

	// 获取重定向地址
	redirectUri, err := url.QueryUnescape(req.FormValue("redirect_uri"))
	if err != nil {
		res.OutErrorState(pkg.Errors.InvalidRequest, "")
		res.InternalError = err
		return nil
	}

	// 创建授权请求
	ret := &pkg.AuthorizeRequest{
		State:       req.FormValue("state"),
		Scope:       req.FormValue("scope"),
		RedirectUri: redirectUri,
		Authorized:  false,
		HttpRequest: req,
	}

	// 获取客户端信息
	ret.Client, err = res.Store.GetClient(req.FormValue("client_id"))
	// 客户端接口未实现
	if err == pkg.Errors.ImplementNotFound.Throw() {
		res.OutErrorState(pkg.Errors.ImplementNotFound, ret.State)
		return nil
	}
	// 客户端获取出错
	if err != nil {
		res.OutErrorState(pkg.Errors.Unexpected, ret.State)
		res.InternalError = err
		return nil
	}
	// 未获取到客户端
	if ret.Client == nil {
		res.OutErrorState(pkg.Errors.UnauthorizedClient, ret.State)
		return nil
	}
	// 未获取到重定向地址(必须要有)
	if ret.Client.GetRedirectUri() == "" {
		res.OutErrorState(pkg.Errors.UnauthorizedClient, ret.State)
		return nil
	}
	// 允许多个重定向地址
	if ret.RedirectUri != "" && s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = pkg.GetFirstUri(ret.Client.GetRedirectUri())
	}
	// 校验重定向地址是否匹配
	if realRedirectUri, err := pkg.ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.AllowMultipleRedirectUri); err != nil {
		res.OutErrorState(pkg.Errors.InvalidRequest, ret.State)
		res.InternalError = err
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}
	// 设置重定向地址
	res.SetRedirect(ret.RedirectUri)
	// 获取请求类型
	requestType := pkg.AuthorizeRequestType(req.FormValue("response_type"))
	// 检查请求类型是否在允许范围
	if s.Config.AllowedAuthorizeTypes.Allow(requestType) {
		switch requestType {
		case pkg.CODE:
			ret.Type = pkg.CODE
			ret.ExpiresIn = s.Config.AuthorizationExpiration
			// 判断挑战代码是否为空
			if codeChallenge := req.FormValue("code_challenge"); len(codeChallenge) == 0 {
				// 判断是否要求请求使用PKCE挑战
				// https://datatracker.ietf.org/doc/html/rfc7636
				if s.Config.RequirePKCEForPublicClients && pkg.CheckClientSecret(ret.Client, "") {
					res.OutErrorState(pkg.Errors.InvalidRequest, ret.State)
					return nil
				}
			} else {
				// 获取挑战方法
				codeChallengeMethod := req.FormValue("code_challenge_method")
				// 未传入则默认 plain
				if len(codeChallengeMethod) == 0 {
					codeChallengeMethod = pkg.PKCE_PLAIN
				}
				// 判断挑战方法是否在允许范围
				if codeChallengeMethod != pkg.PKCE_PLAIN && codeChallengeMethod != pkg.PKCE_S256 {
					res.OutErrorState(pkg.Errors.InvalidRequest, ret.State)
					return nil
				}
				// 判断挑战代码是否包含非法字符
				if matched := pkceMatcher.MatchString(codeChallenge); !matched {
					res.OutErrorState(pkg.Errors.InvalidRequest, ret.State)
					return nil
				}
				ret.CodeChallenge = codeChallenge
				ret.CodeChallengeMethod = codeChallengeMethod
			}
		case pkg.TOKEN:
			ret.Type = pkg.TOKEN
			ret.ExpiresIn = s.Config.AccessExpiration
		}
		return ret
	}
	res.OutErrorState(pkg.Errors.InvalidAuthRequestType, ret.State)
	return nil
}

// 授权请求完成
func (s *Server) FinishAuthorizeRequest(res *pkg.Response, req *http.Request, ar *pkg.AuthorizeRequest) {
	// 处理出错时直接返回
	if !res.State {
		return
	}
	// 设置重定向地址
	res.SetRedirect(ar.RedirectUri)
	// 判断是否已授权
	if ar.Authorized {
		// 授权请求类型是否为令牌
		if ar.Type == pkg.TOKEN {
			res.SetRedirectFragment(true)
			// 请求创建访问令牌,此时不应生成刷新令牌
			ret := &pkg.AccessRequest{
				Type:            pkg.IMPLICIT,
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
			ret := &pkg.Authorize{
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
				res.OutErrorState(pkg.Errors.Unexpected, ar.State)
				res.InternalError = err
				return
			}
			ret.Code = code
			// 保存授权码
			if err = res.Store.SaveAuthorize(ret); err != nil {
				res.OutErrorState(pkg.Errors.Unexpected, ar.State)
				res.InternalError = err
				return
			}
			// 返回授权码和穿透状态
			res.Output["code"] = ret.Code
			res.Output["state"] = ret.State
		}
	} else {
		res.OutErrorState(pkg.Errors.DeniedAccess, ar.State)
	}
}

// 完成访问令牌请求
func (s *Server) FinishAccessRequest(w *pkg.Response, r *http.Request, ar *pkg.AccessRequest) {
	// 处理出错时直接返回
	if !w.State {
		return
	}
	redirectUri := r.FormValue("redirect_uri")
	// 获取重定向地址
	if ar.RedirectUri != "" {
		redirectUri = ar.RedirectUri
	}
	// 判断是否已授权
	if ar.Authorized {
		var ret *pkg.Access
		var err error

		if ar.ForceAccess == nil {
			// 创建访问请求
			ret = &pkg.Access{
				Client:      ar.Client,
				Authorize:   ar.Authorize,
				Access:      ar.Access,
				RedirectUri: redirectUri,
				CreatedAt:   s.Now(),
				ExpiresIn:   ar.ExpiresIn,
				UserData:    ar.UserData,
				Scope:       ar.Scope,
			}
			// 创建访问令牌
			ret.AccessToken, ret.RefreshToken, err = s.AccessTokenGen.GenerateAccessToken(ret, ar.GenerateRefresh)
			if err != nil {
				s.returnError(w, pkg.Errors.FailedCreateToken, err, "finish_access_request=%s", "error generating token")
				return
			}
		} else {
			ret = ar.ForceAccess
		}
		// 存储访问令牌
		if err = w.Store.SaveAccess(ret); err != nil {
			s.returnError(w, pkg.Errors.FailedStoreToken, err, "finish_access_request=%s", "error saving access token")
			return
		}
		// 删除授权令牌
		if ret.Authorize != nil {
			w.Store.RemoveAuthorize(ret.Authorize.Code)
		}
		// 清理过期的旧令牌
		if ret.Access != nil && !s.Config.AllowRetainToken {
			if ret.Access.RefreshToken != "" {
				w.Store.RemoveRefresh(ret.Access.RefreshToken)
			}
			w.Store.RemoveAccess(ret.Access.AccessToken)
		}
		// 输出令牌
		w.Output["access_token"] = ret.AccessToken
		w.Output["token_type"] = s.Config.TokenType
		w.Output["expires_in"] = ret.ExpiresIn
		if ret.RefreshToken != "" {
			w.Output["refresh_token"] = ret.RefreshToken
		}
		if ret.Scope != "" {
			w.Output["scope"] = ret.Scope
		}
	} else {
		s.returnError(w, pkg.Errors.DeniedAccess, nil, "finish_access_request=%s", "authorization failed")
	}
}

// 处理访问令牌请求
func (s *Server) HandleAccessRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 根据设置判断请求类型是否符合要求
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			s.returnError(w, pkg.Errors.InvalidRequest, errors.New("request must be post"), "access_request=%s", "GET request not allowed")
			return nil
		}
	} else if r.Method != "POST" {
		s.returnError(w, pkg.Errors.InvalidRequest, errors.New("request must be post"), "access_request=%s", "request must be POST")
		return nil
	}
	// 分析表单
	err := r.ParseForm()
	if err != nil {
		s.returnError(w, pkg.Errors.InvalidRequest, err, "access_request=%s", "parsing error")
		return nil
	}
	// 获取访问请求类型
	grantType := pkg.AccessRequestType(r.FormValue("grant_type"))
	// 判断类型是否允许
	if s.Config.AllowedAccessTypes.Allow(grantType) {
		switch grantType {
		case pkg.AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case pkg.REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case pkg.PASSWORD:
			return s.handlePasswordRequest(w, r)
		case pkg.CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		case pkg.ASSERTION:
			return s.handleAssertionRequest(w, r)
		}
	}

	s.returnError(w, pkg.Errors.InvalidAccessRequestType, nil, "access_request=%s", "unknown grant type")
	return nil
}

// 处理授权码请求
func (s *Server) handleAuthorizationCodeRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &pkg.AccessRequest{
		Type:            pkg.AUTHORIZATION_CODE,
		Code:            r.FormValue("code"),
		CodeVerifier:    r.FormValue("code_verifier"),
		RedirectUri:     r.FormValue("redirect_uri"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入代码
	if ret.Code == "" {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "code is required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 判断授权码是否有效
	var err error
	ret.Authorize, err = w.Store.GetAuthorize(ret.Code)
	if err != nil {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, err, "auth_code_request=%s", "error loading authorize data")
		return nil
	}
	if ret.Authorize == nil {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "authorization data is nil")
		return nil
	}
	if ret.Authorize.Client == nil {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "authorization client is nil")
		return nil
	}
	if ret.Authorize.Client.GetRedirectUri() == "" {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "client redirect uri is empty")
		return nil
	}
	if ret.Authorize.IsExpiredAt(s.Now()) {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "authorization data is expired")
		return nil
	}
	// 授权码来源必须为特定客户端
	if ret.Authorize.Client.GetId() != ret.Client.GetId() {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "client code does not match")
		return nil
	}
	// 检查重定向地址
	if ret.RedirectUri == "" {
		if s.Config.AllowMultipleRedirectUri {
			ret.RedirectUri = pkg.GetFirstUri(ret.Client.GetRedirectUri())
		} else {
			ret.RedirectUri = ret.Client.GetRedirectUri()
		}
	}
	// 检验重定向地址
	if realRedirectUri, err := pkg.ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.AllowMultipleRedirectUri); err != nil {
		s.returnError(w, pkg.Errors.InvalidRequest, err, "auth_code_request=%s", "error validating client redirect")
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}
	if ret.Authorize.RedirectUri != ret.RedirectUri {
		s.returnError(w, pkg.Errors.InvalidRequest, errors.New("redirect uri is different"), "auth_code_request=%s", "client redirect does not match authorization data")
		return nil
	}
	// 判断是否需要验证PKCE
	if len(ret.Authorize.CodeChallenge) > 0 {
		// 判断挑战代码是否包含非法字符
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			s.returnError(w, pkg.Errors.InvalidRequest, errors.New("code_verifier has invalid format"),
				"auth_code_request=%s", "pkce code challenge verifier does not match")
			return nil
		}
		// 验证PKCE
		codeVerifier := ""
		switch ret.Authorize.CodeChallengeMethod {
		case "", pkg.PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case pkg.PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			s.returnError(w, pkg.Errors.InvalidRequest, nil,
				"auth_code_request=%s", "pkce transform algorithm not supported (rfc7636)")
			return nil
		}
		// 验证不通过
		if codeVerifier != ret.Authorize.CodeChallenge {
			s.returnError(w, pkg.Errors.InvalidAuthMessage, errors.New("code_verifier failed comparison with code_challenge"),
				"auth_code_request=%s", "pkce code verifier does not match challenge")
			return nil
		}
	}
	// 设置返回数据
	ret.Scope = ret.Authorize.Scope
	ret.UserData = ret.Authorize.UserData
	return ret
}

// 扩展令牌范围
func extraTokenScopes(access_scopes, refresh_scopes string) bool {
	// 访问令牌范围
	access_scopes_list := strings.Split(access_scopes, " ")
	// 刷新令牌范围
	refresh_scopes_list := strings.Split(refresh_scopes, " ")

	access_map := make(map[string]int)

	for _, scope := range access_scopes_list {
		if scope == "" {
			continue
		}
		access_map[scope] = 1
	}

	for _, scope := range refresh_scopes_list {
		if scope == "" {
			continue
		}
		if _, ok := access_map[scope]; !ok {
			return true
		}
	}
	return false
}

// 处理刷新令牌请求
func (s *Server) handleRefreshTokenRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &pkg.AccessRequest{
		Type:            pkg.REFRESH_TOKEN,
		Code:            r.FormValue("refresh_token"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入刷新令牌
	if ret.Code == "" {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, nil, "refresh_token=%s", "refresh_token is required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 判断刷新令牌是否有效
	var err error
	ret.Access, err = w.Store.GetRefresh(ret.Code)
	if err != nil {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, err, "refresh_token=%s", "error loading access data")
		return nil
	}
	if ret.Access == nil {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data is nil")
		return nil
	}
	if ret.Access.Client == nil {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data client is nil")
		return nil
	}
	if ret.Access.Client.GetRedirectUri() == "" {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data client redirect uri is empty")
		return nil
	}
	// 授权码来源必须为特定客户端
	if ret.Access.Client.GetId() != ret.Client.GetId() {
		s.returnError(w, pkg.Errors.InvalidClientInfo, errors.New("client id must be the same from previous token"), "refresh_token=%s, current=%v, previous=%v", "client mismatch", ret.Client.GetId(), ret.Access.Client.GetId())
		return nil

	}
	// 设置返回数据
	ret.RedirectUri = ret.Access.RedirectUri
	ret.UserData = ret.Access.UserData
	if ret.Scope == "" {
		ret.Scope = ret.Access.Scope
	}
	// 扩展令牌范围
	if extraTokenScopes(ret.Access.Scope, ret.Scope) {
		msg := "the requested scope must not include any scope not originally granted by the resource owner"
		s.returnError(w, pkg.Errors.DeniedAccess, errors.New(msg), "refresh_token=%s", msg)
		return nil
	}
	return ret
}

// 处理密码式请求
func (s *Server) handlePasswordRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &pkg.AccessRequest{
		Type:            pkg.PASSWORD,
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入用户名和密码
	if ret.Username == "" || ret.Password == "" {
		s.returnError(w, pkg.Errors.InvalidRequest, nil, "handle_password=%s", "username and pass required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 设置重定向地址
	if s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = pkg.GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 处理客户端凭证请求
func (s *Server) handleClientCredentialsRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &pkg.AccessRequest{
		Type:            pkg.CLIENT_CREDENTIALS,
		Scope:           r.FormValue("scope"),
		GenerateRefresh: false,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 设置重定向地址
	if s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = pkg.GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 处理断言请求
func (s *Server) handleAssertionRequest(w *pkg.Response, r *http.Request) *pkg.AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求,此时不应生成刷新令牌
	ret := &pkg.AccessRequest{
		Type:            pkg.ASSERTION,
		Scope:           r.FormValue("scope"),
		AssertionType:   r.FormValue("assertion_type"),
		Assertion:       r.FormValue("assertion"),
		GenerateRefresh: false,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入断言
	if ret.AssertionType == "" || ret.Assertion == "" {
		s.returnError(w, pkg.Errors.InvalidAuthMessage, nil, "handle_assertion_request=%s", "assertion and assertion_type required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 设置重定向地址
	if s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = pkg.GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 获取客户端
func (s Server) getClient(auth *pkg.BasicAuth, Store pkg.Store, w *pkg.Response) pkg.Client {
	client, err := Store.GetClient(auth.Username)
	if err == pkg.Errors.ImplementNotFound.Throw() {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "get_client=%s", "not found")
		return nil
	}
	if err != nil {
		s.returnError(w, pkg.Errors.FailureStore, err, "get_client=%s", "error finding client")
		return nil
	}
	if client == nil {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "get_client=%s", "client is nil")
		return nil
	}

	if !pkg.CheckClientSecret(client, auth.Password) {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "get_client=%s, client_id=%v", "client check failed", client.GetId())
		return nil
	}

	if client.GetRedirectUri() == "" {
		s.returnError(w, pkg.Errors.InvalidClientInfo, nil, "get_client=%s", "client redirect uri is empty")
		return nil
	}
	return client
}

// 返回错误信息
func (s Server) returnError(w *pkg.Response, responseError pkg.CustomError, internalError error, debugFormat string, debugArgs ...interface{}) {
	format := "error=%v, internal_error=%#v " + debugFormat

	w.InternalError = internalError
	w.OutError(responseError)

	s.Logger.Printf(format, append([]interface{}{responseError, internalError}, debugArgs...)...)
}

// 获取客户端授权信息
func (s Server) getClientAuth(res *pkg.Response, req *http.Request, allowClientSecretInParams bool) *pkg.BasicAuth {
	// 允许密钥通过请求体传输
	if allowClientSecretInParams {
		// 允许不受密码保护的身份验证
		if _, hasSecret := req.Form["client_secret"]; hasSecret {
			auth := &pkg.BasicAuth{
				Username: req.FormValue("client_id"),
				Password: req.FormValue("client_secret"),
			}
			if auth.Username != "" {
				return auth
			}
		}
	}
	// 从请求中获取 Basic 验证信息
	auth, err := pkg.GetBasicAuth(req)
	if err != nil {
		s.returnError(res, pkg.Errors.InvalidRequest, err, "get_client_auth=%s", "check auth error")
		return nil
	}
	if auth == nil {
		ce := pkg.Errors.UnauthorizedClient
		s.returnError(res, ce, ce.Throw(), "get_client_auth=%s", "client authentication not sent")
		return nil
	}
	return auth
}

// 输出JSON
func OutputJSON(res *pkg.Response, resWriter http.ResponseWriter) error {
	// 添加响应头
	for i, k := range res.Headers {
		for _, v := range k {
			resWriter.Header().Add(i, v)
		}
	}
	// 判断是否重定向
	if res.Type == pkg.REDIRECT {
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
