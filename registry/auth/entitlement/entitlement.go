package entitlement

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/core/http"
	"github.com/Azure/azure-sdk-for-go/core/tls"
	//"log"
	"io"
	"io/ioutil"
	//"strconv"
)

type Entitlement struct {
	EndPoint string
}

type requestData struct {
	EntitlementData string
	Path            string
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
	var reqData requestData
	var resData ResponseData
	var err error
	reqData.EntitlementData = entitlementData
	reqData.Path = path

	jsondata, marshalerr := json.Marshal(reqData)

	if marshalerr != nil {
		return resData, marshalerr
	}

	if resData, err = execute("POST", entitlement.EndPoint, jsondata, "/verify"); err != nil {
		return resData, err
	}

	return resData, nil

}

func execute(verb, url string, content []byte, endPoint string) (ResponseData, error) {
	var data ResponseData
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defaultClient := &http.Client{Transport: transport}
	request, err := http.NewRequest(verb, endPoint+url, bytes.NewBuffer(content))

	if err != nil {
		return data, err
	}

	response, err := defaultClient.Do(request)

	fmt.Println("calling service with: ", string(content[:]))
	if err != nil {
		return data, err
	}

	defer response.Body.Close()

	statusCode := response.StatusCode

	if statusCode != 200 {
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
