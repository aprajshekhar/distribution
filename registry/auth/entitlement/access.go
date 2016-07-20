// access
package entitlement

import (
	"fmt"

	"net/http"
	"strings"

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

	if req.Header.Get("SSL_CLIENT_CERT") == "" {

		return nil, &challenge{
			realm: ac.realm,
			err:   fmt.Errorf("Authentication Failure"),
		}
	}

	pemStr := req.Header.Get("SSL_CLIENT_CERT")
	repoName := getRepoName(req.RequestURI)
	//if we are not getting any repo name
	//and the the URI requested is /v2/ (ping)
	//then don't call authentication service
	if repoName == "" && "/v2/" == req.RequestURI {
		return auth.WithUser(ctx, auth.UserInfo{Name: "entitled-ping"}), nil
	}

	path := fmt.Sprintf("/content/dist/rhel/server/7/7Server/x86_64/containers/registry/%s", repoName)

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

func getRepoName(uri string) string {
	comps := [...]string{"manifests"}
	var name string
	for _, element := range comps {
		if strings.Contains(uri, element) {
			name = uri[len("/v2/") : strings.LastIndex(uri, element)-1]
		} else {
			name = ""
		}
	}
	return name
}
