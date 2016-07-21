package entitlement

import (
	"bytes"
	"encoding/json"
	"fmt"

	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	log "github.com/Sirupsen/logrus"
)

type Entitlement struct {
	EndPoint string
}

type requestData struct {
	Data data `json:"data"`
}

type data struct {
	EntitlementData string `json:"pem_data"`
	Path            string `json:"path"`
}

type ResponseData struct {
	Verified string `json:"verified"`
}

func NewEntitlement(servicePath string) *Entitlement {
	entitlement := &Entitlement{
		EndPoint: servicePath,
	}
	return entitlement
}

func (entitlement *Entitlement) CheckEntitlement(entitlementData, path string) (ResponseData, error) {
	var detail data
	var reqData requestData
	var resData ResponseData
	var err error
	detail.EntitlementData = entitlementData
	detail.Path = path
	reqData.Data = detail
	jsondata, marshalerr := json.Marshal(reqData)

	if marshalerr != nil {
		return resData, marshalerr
	}

	if resData, err = execute("POST", "/verify", jsondata, entitlement.EndPoint); err != nil {
		return resData, err
	}
	log.Debug("received response data: ", resData)
	return resData, nil

}

func execute(verb, url string, content []byte, endPoint string) (ResponseData, error) {
	var data ResponseData
	fmt.Println("uri ", endPoint+url)
	//	transport := &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//	}
	//defaultClient := &http.Client{Transport: transport}
	request, err := http.NewRequest(verb, endPoint+url, bytes.NewBuffer(content))

	if err != nil {
		return data, err
	}
	request.Header.Set("Content-Type", "application/json")
	dump1, _ := httputil.DumpRequest(request, true)
	log.Debug("req details for auth service")
	log.Debug(string(dump1))

	response, err := http.DefaultClient.Do(request)

	if err != nil {
		log.Debug("error in call:", err)
		return data, err
	}

	defer response.Body.Close()

	statusCode := response.StatusCode
	log.Debug("status code:", statusCode)
	if statusCode != 200 {
		responseBody, _ := getResponse(response)
		log.Debug("error body: ", string(responseBody[:]))
		return data, fmt.Errorf("Received non OK status %s from service", string(statusCode))
	}

	var responseBody []byte
	responseBody, err = getResponse(response)
	if err != nil {
		return data, err
	}

	if err = json.Unmarshal(responseBody, &data); err != nil {
		return data, err
	}

	return data, nil

}

func getResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	out, err := ioutil.ReadAll(response.Body)
	if err == io.EOF {
		err = nil
	}
	return out, err
}
