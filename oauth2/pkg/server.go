/*
服务器

BetaX Unified Authorization Center
Copyright © 2023 SkyeZhang <skai-zhang@hotmail.com>
*/

package pkg

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/skye-z/uac/oauth2"
)

type Server struct {
	Config            *Config
	Store             Store
	AuthorizeTokenGen AuthorizeTokenGen
	AccessTokenGen    AccessTokenGen
	Now               func() time.Time
	Logger            oauth2.Logger
}

// 创建服务器
func NewServer(config *Config, store Store) *Server {
	logger := &oauth2.LoggerConsole{}
	logger.Printf("Create server")
	logger.Printf("Loading %s storage", store.GetName())
	return &Server{
		Config:            config,
		Store:             store,
		AuthorizeTokenGen: &AuthorizeTokenGenDefault{},
		AccessTokenGen:    &AccessTokenGenDefault{},
		Now:               time.Now,
		Logger:            logger,
	}
}

// 创建响应
func (s *Server) NewResponse() *Response {
	r := NewResponse(s.Store)
	r.Code = s.Config.ErrorStatusCode
	return r
}

// 完成访问令牌请求
func (s *Server) FinishAccessRequest(w *Response, r *http.Request, ar *AccessRequest) {
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
		var ret *Access
		var err error

		if ar.ForceAccess == nil {
			// 创建访问请求
			ret = &Access{
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
				s.returnError(w, oauth2.Errors.FailedCreateToken, err, "finish_access_request=%s", "error generating token")
				return
			}
		} else {
			ret = ar.ForceAccess
		}
		// 存储访问令牌
		if err = w.Store.SaveAccess(ret); err != nil {
			s.returnError(w, oauth2.Errors.FailedStoreToken, err, "finish_access_request=%s", "error saving access token")
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
		s.returnError(w, oauth2.Errors.DeniedAccess, nil, "finish_access_request=%s", "authorization failed")
	}
}

// 处理访问令牌请求
func (s *Server) HandleAccessRequest(w *Response, r *http.Request) *AccessRequest {
	// 根据设置判断请求类型是否符合要求
	if r.Method == "GET" {
		if !s.Config.AllowGetAccessRequest {
			s.returnError(w, oauth2.Errors.InvalidRequest, errors.New("request must be post"), "access_request=%s", "GET request not allowed")
			return nil
		}
	} else if r.Method != "POST" {
		s.returnError(w, oauth2.Errors.InvalidRequest, errors.New("request must be post"), "access_request=%s", "request must be POST")
		return nil
	}
	// 分析表单
	err := r.ParseForm()
	if err != nil {
		s.returnError(w, oauth2.Errors.InvalidRequest, err, "access_request=%s", "parsing error")
		return nil
	}
	// 获取访问请求类型
	grantType := AccessRequestType(r.FormValue("grant_type"))
	// 判断类型是否允许
	if s.Config.AllowedAccessTypes.Allow(grantType) {
		switch grantType {
		case AUTHORIZATION_CODE:
			return s.handleAuthorizationCodeRequest(w, r)
		case REFRESH_TOKEN:
			return s.handleRefreshTokenRequest(w, r)
		case PASSWORD:
			return s.handlePasswordRequest(w, r)
		case CLIENT_CREDENTIALS:
			return s.handleClientCredentialsRequest(w, r)
		case ASSERTION:
			return s.handleAssertionRequest(w, r)
		}
	}

	s.returnError(w, oauth2.Errors.InvalidAccessRequestType, nil, "access_request=%s", "unknown grant type")
	return nil
}

// 处理授权码请求
func (s *Server) handleAuthorizationCodeRequest(w *Response, r *http.Request) *AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &AccessRequest{
		Type:            AUTHORIZATION_CODE,
		Code:            r.FormValue("code"),
		CodeVerifier:    r.FormValue("code_verifier"),
		RedirectUri:     r.FormValue("redirect_uri"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入代码
	if ret.Code == "" {
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "code is required")
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
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, err, "auth_code_request=%s", "error loading authorize data")
		return nil
	}
	if ret.Authorize == nil {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "authorization data is nil")
		return nil
	}
	if ret.Authorize.Client == nil {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "authorization client is nil")
		return nil
	}
	if ret.Authorize.Client.GetRedirectUri() == "" {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "auth_code_request=%s", "client redirect uri is empty")
		return nil
	}
	if ret.Authorize.IsExpiredAt(s.Now()) {
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "authorization data is expired")
		return nil
	}
	// 授权码来源必须为特定客户端
	if ret.Authorize.Client.GetId() != ret.Client.GetId() {
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, nil, "auth_code_request=%s", "client code does not match")
		return nil
	}
	// 检查重定向地址
	if ret.RedirectUri == "" {
		if s.Config.AllowMultipleRedirectUri {
			ret.RedirectUri = GetFirstUri(ret.Client.GetRedirectUri())
		} else {
			ret.RedirectUri = ret.Client.GetRedirectUri()
		}
	}
	// 检验重定向地址
	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.AllowMultipleRedirectUri); err != nil {
		s.returnError(w, oauth2.Errors.InvalidRequest, err, "auth_code_request=%s", "error validating client redirect")
		return nil
	} else {
		ret.RedirectUri = realRedirectUri
	}
	if ret.Authorize.RedirectUri != ret.RedirectUri {
		s.returnError(w, oauth2.Errors.InvalidRequest, errors.New("redirect uri is different"), "auth_code_request=%s", "client redirect does not match authorization data")
		return nil
	}
	// 判断是否需要验证PKCE
	if len(ret.Authorize.CodeChallenge) > 0 {
		// 判断挑战代码是否包含非法字符
		if matched := pkceMatcher.MatchString(ret.CodeVerifier); !matched {
			s.returnError(w, oauth2.Errors.InvalidRequest, errors.New("code_verifier has invalid format"),
				"auth_code_request=%s", "pkce code challenge verifier does not match")
			return nil
		}
		// 验证PKCE
		codeVerifier := ""
		switch ret.Authorize.CodeChallengeMethod {
		case "", PKCE_PLAIN:
			codeVerifier = ret.CodeVerifier
		case PKCE_S256:
			hash := sha256.Sum256([]byte(ret.CodeVerifier))
			codeVerifier = base64.RawURLEncoding.EncodeToString(hash[:])
		default:
			s.returnError(w, oauth2.Errors.InvalidRequest, nil,
				"auth_code_request=%s", "pkce transform algorithm not supported (rfc7636)")
			return nil
		}
		// 验证不通过
		if codeVerifier != ret.Authorize.CodeChallenge {
			s.returnError(w, oauth2.Errors.InvalidAuthMessage, errors.New("code_verifier failed comparison with code_challenge"),
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
func (s *Server) handleRefreshTokenRequest(w *Response, r *http.Request) *AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &AccessRequest{
		Type:            REFRESH_TOKEN,
		Code:            r.FormValue("refresh_token"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入刷新令牌
	if ret.Code == "" {
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, nil, "refresh_token=%s", "refresh_token is required")
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
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, err, "refresh_token=%s", "error loading access data")
		return nil
	}
	if ret.Access == nil {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data is nil")
		return nil
	}
	if ret.Access.Client == nil {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data client is nil")
		return nil
	}
	if ret.Access.Client.GetRedirectUri() == "" {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "refresh_token=%s", "access data client redirect uri is empty")
		return nil
	}
	// 授权码来源必须为特定客户端
	if ret.Access.Client.GetId() != ret.Client.GetId() {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, errors.New("client id must be the same from previous token"), "refresh_token=%s, current=%v, previous=%v", "client mismatch", ret.Client.GetId(), ret.Access.Client.GetId())
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
		s.returnError(w, oauth2.Errors.DeniedAccess, errors.New(msg), "refresh_token=%s", msg)
		return nil
	}
	return ret
}

// 处理密码式请求
func (s *Server) handlePasswordRequest(w *Response, r *http.Request) *AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &AccessRequest{
		Type:            PASSWORD,
		Username:        r.FormValue("username"),
		Password:        r.FormValue("password"),
		Scope:           r.FormValue("scope"),
		GenerateRefresh: true,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入用户名和密码
	if ret.Username == "" || ret.Password == "" {
		s.returnError(w, oauth2.Errors.InvalidRequest, nil, "handle_password=%s", "username and pass required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 设置重定向地址
	if s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 处理客户端凭证请求
func (s *Server) handleClientCredentialsRequest(w *Response, r *http.Request) *AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求
	ret := &AccessRequest{
		Type:            CLIENT_CREDENTIALS,
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
		ret.RedirectUri = GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 处理断言请求
func (s *Server) handleAssertionRequest(w *Response, r *http.Request) *AccessRequest {
	// 获取客户端授权信息
	auth := s.getClientAuth(w, r, s.Config.AllowClientSecretInParams)
	if auth == nil {
		return nil
	}
	// 创建访问请求,此时不应生成刷新令牌
	ret := &AccessRequest{
		Type:            ASSERTION,
		Scope:           r.FormValue("scope"),
		AssertionType:   r.FormValue("assertion_type"),
		Assertion:       r.FormValue("assertion"),
		GenerateRefresh: false,
		ExpiresIn:       s.Config.AccessExpiration,
		HttpRequest:     r,
	}
	// 检查是否传入断言
	if ret.AssertionType == "" || ret.Assertion == "" {
		s.returnError(w, oauth2.Errors.InvalidAuthMessage, nil, "handle_assertion_request=%s", "assertion and assertion_type required")
		return nil
	}
	// 判断客户端是否有效
	if ret.Client = s.getClient(auth, w.Store, w); ret.Client == nil {
		return nil
	}
	// 设置重定向地址
	if s.Config.AllowMultipleRedirectUri {
		ret.RedirectUri = GetFirstUri(ret.Client.GetRedirectUri())
	} else {
		ret.RedirectUri = ret.Client.GetRedirectUri()
	}
	return ret
}

// 获取客户端
func (s Server) getClient(auth *BasicAuth, Store Store, w *Response) Client {
	client, err := Store.GetClient(auth.Username)
	if err == oauth2.Errors.ImplementNotFound.Throw() {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "get_client=%s", "not found")
		return nil
	}
	if err != nil {
		s.returnError(w, oauth2.Errors.FailureStore, err, "get_client=%s", "error finding client")
		return nil
	}
	if client == nil {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "get_client=%s", "client is nil")
		return nil
	}

	if !CheckClientSecret(client, auth.Password) {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "get_client=%s, client_id=%v", "client check failed", client.GetId())
		return nil
	}

	if client.GetRedirectUri() == "" {
		s.returnError(w, oauth2.Errors.InvalidClientInfo, nil, "get_client=%s", "client redirect uri is empty")
		return nil
	}
	return client
}

// 返回错误信息
func (s Server) returnError(w *Response, responseError oauth2.CustomError, internalError error, debugFormat string, debugArgs ...interface{}) {
	format := "error=%v, internal_error=%#v " + debugFormat

	w.InternalError = internalError
	w.OutError(responseError)

	s.Logger.Printf(format, append([]interface{}{responseError, internalError}, debugArgs...)...)
}
