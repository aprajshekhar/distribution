// entitlement
package entitlement

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/distribution/context"
	"github.com/docker/distribution/registry/auth"
)

// accessController provides a simple implementation of auth.AccessController
// that simply checks for a non-empty Authorization header. It is useful for
// demonstration and testing.
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

// Authorized simply checks for the existence of the authorization header,
// responding with a bearer challenge if it doesn't exist.
func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	var resData ResponseData
	var err1 error
	req, err := context.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	//	if req.Header.Get("SSL_CLIENT_CERT") == "" {
	//		fmt.Println("repo name: %s", getRepoName(req.RequestURI))
	//		fmt.Println("SSL CERT: %s", req.Header.Get("SSL_CLIENT_CERT"))
	//		return nil, &challenge{
	//			realm: ac.realm,
	//			err:   fmt.Errorf("Authentication Failure"),
	//		}
	//	}

	pemStr := req.Header.Get("SSL_CLIENT_CERT")
	repoName := getName(ctx)
	//if we are not getting any repo name
	//and the the URI requested is /v2/ (ping)
	//then don't call authentication service
	log.Debugln("requestURI: ", req.RequestURI)
	log.Debugln("requested repo name: ", getName(ctx))
	if skipAuth(req) {
		log.Debugln("Returning without calling authentication servie")
		return auth.WithUser(ctx, auth.UserInfo{Name: "entitled-ping"}), nil
	}

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
		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure"),
		}
	}

	if resData.Verified != "true" {
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

// SetChallenge sets the WWW-Authenticate value for the response.
func (ac challenge) SetHeaders(w http.ResponseWriter) {
	//w.Header().Add("WWW-Authenticate", ac.challengeParams())
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
