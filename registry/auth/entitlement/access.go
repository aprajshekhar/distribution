// Package entitlement provides entitlement certificate based authentication
// scheme that checks whether the requested path is present in the entitlement
// certificate or not.
//
// This authentication must be used under TLS, as non SSL requests won't have the
// certificate data in the request
package entitlement

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

// accessController provides a implementation of auth.AccessController
// that checks for a non-empty SSL CLIENT header, which is then used for
// entitlement cert based authentication. It is useful for
// candlepin issued entitlement cert based auth.
type accessController struct {
	realm   string
	service *Entitlement
}

var _ auth.AccessController = &accessController{}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {
	realm, present := options["realm"]
	if _, ok := realm.(string); !present || !ok {
		return nil, fmt.Errorf(`"realm" must be set for entitlement access controller`)
	}

	service, present := options["servicePath"]
	if _, ok := service.(string); !present || !ok {
		return nil, fmt.Errorf(`"servicePath" must be set for entitlement access controller`)
	}

	//var e Entitlement
	e := NewEntitlement(service.(string))

	return &accessController{realm: realm.(string), service: e}, nil
}

// Authorized simply checks for the existence of the SSL CLIENT headers,
// using which entitlement check is done
func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	var resData ResponseData
	var err1 error
	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	if req.Header.Get("SSL_CLIENT_CERT") == "" {
		log.Debugln("repo name: %s", getRepoName(req.RequestURI))

		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure"),
		}
	}

	pemStr := req.Header.Get("SSL_CLIENT_CERT")
	log.Debugln("SSL CERT: %s", pemStr)
	repoName := getName(ctx)
	//if it is a push request
	//or the the URI requested is /v2/ (ping)
	//then don't call authentication service
	log.Debugln("requestURI: ", req.RequestURI)
	log.Debugln("requested repo name: ", getName(ctx))
	if skipAuth(req) {
		log.Debugln("Returning without calling authentication servie")
		return auth.WithUser(ctx, auth.UserInfo{Name: "entitled-ping"}), nil
	}

	// check for repo name being empty. If repo name is empty
	// and the URI is not for ping, return authentication error
	if "/v2/" != req.RequestURI && repoName == "" {
		log.Errorln("No repo name retrieved. This should not happen")
		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure as no repo name has been supplied"),
		}
	}

	libraryName := repoName[:strings.LastIndex(repoName, "/")+1]
	log.Debugln("Computed library name: ", libraryName)
	path := fmt.Sprintf("/content/dist/rhel/server/7/7Server/x86_64/containers/registry/%s", libraryName)

	if resData, err1 = ac.service.CheckEntitlement(pemStr, path); err1 != nil {
		log.Errorln("Service returned error: ", err1)
		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure"),
		}
	}

	if resData.Verified != "true" {
		log.Errorln("Service returned unauthenticated/unauthorized")
		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure"),
		}
	}

	return auth.WithUser(ctx, auth.UserInfo{Name: "entitled"}), nil
}

type challenge struct {
	realm string
	err   error
}

// Error returns the internal error string for this authChallenge.
func (ac challenge) Error() string {
	return ac.err.Error()
}

// SetChallenge sets the WWW-Authenticate value for the response. However
// that is not required for entitlement based auth. Hence, providing empty
// implementation
func (ac challenge) SetHeaders(w http.ResponseWriter) {

}

var _ auth.Challenge = challenge{}

// init handles registering the entitlement auth backend.
func init() {
	auth.Register("entitlement", auth.InitFunc(newAccessController))
}

func getName(ctx context.Context) (name string) {
	return context.GetStringValue(ctx, "vars.name")
}

func skipAuth(req *http.Request) bool {
	return "/v2/" == req.RequestURI || req.Method == "POST" || req.Method == "HEAD" || req.Method == "PATCH" || req.Method == "PUT"
}
