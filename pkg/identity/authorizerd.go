package identity

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	authorizerd "github.com/AthenZ/athenz-authorizer/v5"
	"github.com/pkg/errors"
	"github.com/yahoo/k8s-athenz-identity/pkg/log"
)

func Authorizerd(idConfig *IdentityConfig, stopChan <-chan struct{}) error {

	if idConfig.AuthorizationServerAddr == "" || idConfig.AuthorizationPolicyDomains == "" || idConfig.TokenType == "" {
		log.Infof("Authorizer is disabled with empty options: address[%s], domains[%s], authorizer-type[%s]", idConfig.AuthorizationServerAddr, idConfig.AuthorizationPolicyDomains, idConfig.TokenType)
		return nil
	}

	handler, err := InitIdentityHandler(idConfig)
	if err != nil {
		log.Errorf("Failed to initialize client for authorizer: %s", err.Error())
		return err
	}

	go func() {

		if idConfig.Init {
			log.Infof("Authorizer is disabled for init mode: address[%s]", idConfig.AuthorizationServerAddr)
			return
		}

		authorizerURL, err := url.Parse(idConfig.Endpoint)
		if err != nil {
			log.Errorf("Failed to parse url for authorizer from endpoint[%s]: %s", idConfig.Endpoint, err.Error())
		}
		authorizerClient := &http.Client{
			Transport: handler.Client().Transport,
			Timeout:   handler.Client().Timeout,
		}
		aci, _ := time.ParseDuration(idConfig.AuthorizationCacheInterval)
		daemon, err := authorizerd.New(
			authorizerd.WithAthenzURL(authorizerURL.Host+authorizerURL.Path),
			authorizerd.WithHTTPClient(authorizerClient),
			authorizerd.WithAthenzDomains(strings.Split(idConfig.AuthorizationPolicyDomains, ",")...),
			authorizerd.WithPolicyRefreshPeriod(idConfig.PolicyRefreshInterval),
			authorizerd.WithPubkeyRefreshPeriod(idConfig.PublicKeyRefreshInterval),
			authorizerd.WithCacheExp(aci),
			//authorizerd.WithEnablePubkeyd(),
			authorizerd.WithEnablePolicyd(),
			authorizerd.WithEnableJwkd(),
			authorizerd.WithAccessTokenParam(authorizerd.NewAccessTokenParam(true, idConfig.EnableMTLSCertificateBoundAccessToken, "", "", false, nil)),
			authorizerd.WithEnableRoleToken(),
			authorizerd.WithRoleAuthHeader(idConfig.RoleAuthHeader),
			//authorizerd.WithEnableRoleCert(),
			//authorizerd.WithRoleCertURIPrefix("athenz://role/"),
		)
		if err != nil {
			log.Errorf("Failed to initialize authorizer: %s", err.Error())
		}
		authzctx := context.Background()
		if err = daemon.Init(authzctx); err != nil {
			log.Errorf("Failed to start authorizer: %s", err.Error())
		}
		authorize := func(cert *x509.Certificate, at, rt, action, resource string) (principal authorizerd.Principal, err error) {

			if cert != nil && at == "" {
				principal, err = daemon.AuthorizeRoleCert(authzctx, []*x509.Certificate{cert}, action, resource)
				if err != nil {
					err = errors.Wrap(err, fmt.Sprintf("Authorization failed with role certificate, action[%s], resource[%s]: %s", action, resource, err.Error()))
					log.Debugf("Authorization failed: %s", err.Error())
				}
				if principal != nil {
					return principal, nil
				}
			}
			if at != "" {
				principal, err = daemon.AuthorizeAccessToken(authzctx, at, action, resource, cert)
				if err != nil {
					err = errors.Wrap(err, fmt.Sprintf("Authorization failed with access token, action[%s], resource[%s]: %s", action, resource, err.Error()))
					log.Debugf("Authorization failed: %s", err.Error())
				}
				if principal != nil {
					return principal, nil
				}
			}
			if rt != "" {
				principal, err = daemon.AuthorizeRoleToken(authzctx, rt, action, resource)
				if err != nil {
					err = errors.Wrap(err, fmt.Sprintf("Authorization failed with role token, action[%s], resource[%s]: %s", action, resource, err.Error()))
					log.Debugf("Authorization failed: %s", err.Error())
				}
				if principal != nil {
					return principal, nil
				}
			}

			log.Infof("Authorization failed: %s", err.Error())

			return nil, err
		}

		authorizerHandler := func(w http.ResponseWriter, r *http.Request) {
			actionHeader := "X-Athenz-Action"
			resourceHeader := "X-Athenz-Resource"
			action := r.Header.Get(actionHeader)
			resource := r.Header.Get(resourceHeader)
			accessTokenHeader := "Authorization"
			accessTokenHeaderValue := strings.Split(r.Header.Get(accessTokenHeader), " ")
			at := accessTokenHeaderValue[len(accessTokenHeaderValue)-1]
			rt := r.Header.Get(idConfig.RoleAuthHeader)
			certificateHeader := "X-Athenz-Certificate"
			certificatePEM, _ := url.QueryUnescape(r.Header.Get(certificateHeader))
			var cert *x509.Certificate
			var principal authorizerd.Principal

			// returns HTTP status codes denpending on the results
			// https://pkg.go.dev/net/http

			if (at == "" && rt == "" && certificatePEM == "") || action == "" || resource == "" {
				log.Infof("Required http headers are not set: %s len(%d), %s len(%d), %s len(%d), action[%s], resource[%s]",
					accessTokenHeader, len(at), idConfig.RoleAuthHeader, len(rt), certificateHeader, len(certificatePEM), action, resource)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// OR logic on multiple credentials
			// https://github.com/AthenZ/athenz-authorizer/blob/2c7a05296acbf9dcb1bd751415e430593339b6d1/authorizerd.go#L489
			if certificatePEM != "" {
				block, _ := pem.Decode([]byte(certificatePEM))
				if block == nil {
					log.Infof("Malformed PEM certificate was set: %s[%s]", certificateHeader, certificatePEM)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				cert, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Infof("Malformed X.509 certificate was set: %s[%s]", certificateHeader, certificatePEM)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}

			principal, err := authorize(cert, at, rt, action, resource)
			if err != nil || principal == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-Athenz-Principal", principal.Name())
			w.Header().Set("X-Athenz-Domain", principal.Domain())
			w.Header().Set("X-Athenz-Role", strings.Join(principal.Roles(), ","))
			w.Header().Set("X-Athenz-Issued-At", fmt.Sprintf("%d", principal.IssueTime()))
			w.Header().Set("X-Athenz-Expires-At", fmt.Sprintf("%d", principal.ExpiryTime()))
			w.Header().Set("X-Athenz-AuthorizedRoles", strings.Join(principal.AuthorizedRoles(), ","))
			if c, ok := principal.(authorizerd.OAuthAccessToken); ok {
				w.Header().Set("X-Athenz-Client-ID", c.ClientID())
			}

			result := map[string]string{}
			result["principal"] = principal.Name()
			result["domain"] = principal.Domain()
			result["role"] = strings.Join(principal.Roles(), ",")
			result["issued-at"] = fmt.Sprintf("%d", principal.IssueTime())
			result["expires-at"] = fmt.Sprintf("%d", principal.ExpiryTime())
			result["authorizedroles"] = strings.Join(principal.AuthorizedRoles(), ",")
			response, err := json.Marshal(result)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Infof("Authorization succeeded with %s len(%d), %s len(%d), %s len(%d), action[%s], resource[%s] but failed to prepare response: %s",
					accessTokenHeader, len(at), idConfig.RoleAuthHeader, len(rt), certificateHeader, len(certificatePEM), action, resource, err.Error())
				return
			}

			w.WriteHeader(http.StatusOK)
			io.WriteString(w, string(response))
		}

		httpServer := &http.Server{
			Addr:    idConfig.AuthorizationServerAddr,
			Handler: http.HandlerFunc(authorizerHandler),
		}

		go func() {
			log.Infof("Starting authorizer: domains[%s]", idConfig.AuthorizationPolicyDomains)

			for err := range daemon.Start(authzctx) {
				log.Errorf("Failed to get initial authorizers after multiple retries: %s", err.Error())
			}
		}()

		go func() {
			log.Infof("Starting authorization server: address[%s]", idConfig.AuthorizationServerAddr)

			if err := httpServer.ListenAndServe(); err != nil {
				log.Errorf("Failed to start authorizer: %s", err.Error())
			}
		}()

		<-stopChan
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		httpServer.SetKeepAlivesEnabled(false)
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Errorf("Failed to shutdown authorizer: %s", err.Error())
		}
	}()

	return nil
}
