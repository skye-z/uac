package main

import (
	"log"
	"net/http"

	oauth2pkg "github.com/skye-z/uac/oauth2/pkg"
	"github.com/skye-z/uac/uac-test/model"
)

func main() {
	server := oauth2pkg.NewServer(oauth2pkg.NewServerConfig(), model.NewTestStorage())

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			// 登录页面

			// ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		oauth2pkg.OutputJSON(resp, w)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		oauth2pkg.OutputJSON(resp, w)
	})

	log.Print("[UAC-Test] Test server started")
	http.ListenAndServe(":12600", nil)
}
