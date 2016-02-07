package neverbounce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

var API_BASE_URL = "https://api.neverbounce.com/v3"

type NeverBounce struct {
	ApiUsername string
	ApiKey      string
	Auth        *AuthenticationResponse
	client      *http.Client
}

type AuthenticationResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type SingleEmailRequestResponse struct {
	Success       bool    `json:"success"`
	Result        int     `json:"result"`
	ResultDetails int     `json:"result_details"`
	ExecutionTime float64 `json:"execution_time"`
	ErrorCode     int     `json:"error_code"`
	ErrorMsg      string  `json:"error_msg"`
}

func NewNeverBounce(apiUsername, apiKey string) *NeverBounce {
	nb := &NeverBounce{
		ApiUsername: apiUsername,
		ApiKey:      apiKey,
		client:      &http.Client{},
	}

	return nb
}

// Authenticate will issue an OAUTH2 authentication request and save authentication
// response, which contains the access token for future API requests
func (n *NeverBounce) Authenticate() error {
	if n.ApiUsername == "" || n.ApiKey == "" {
		return errors.New("Missing API Username and/or API Key")
	}

	reqURL := API_BASE_URL + "/access_token"
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	r, _ := http.NewRequest("POST", reqURL, bytes.NewBufferString(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(n.ApiUsername, n.ApiKey)

	resp, err := n.client.Do(r)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		var errorBody []byte

		if resp.Body != nil {
			defer resp.Body.Close()
			errorBody, _ = ioutil.ReadAll(resp.Body)
		}

		return errors.New(fmt.Sprintf("Received error response from server for authentication request: %s", errorBody))
	}

	if resp.Body == nil {
		return errors.New("No body received from authentication response")
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var authResponse *AuthenticationResponse

	err = decoder.Decode(&authResponse)
	if err != nil {
		return err
	}

	n.Auth = authResponse
	log.Println(fmt.Sprintf("Successfully authenticated: %#v", n.Auth))

	return nil
}

// ValidateEmail will validate a single email address
//
// Returns true if valid, false otherwise
func (n *NeverBounce) ValidateEmail(emailAddr string) (bool, error) {
	if n.Auth == nil {
		return false, errors.New("Authorization missing. Authenticate() must be called first before making API requests")
	}

	reqURL := API_BASE_URL + "/single"
	data := url.Values{}
	data.Set("access_token", n.Auth.AccessToken)
	data.Set("email", emailAddr)

	r, _ := http.NewRequest("POST", reqURL, bytes.NewBufferString(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(r)
	if err != nil {
		return false, err
	}

	if resp.Body == nil {
		return false, errors.New("No body received from authentication response")
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var singleEmailReqResp *SingleEmailRequestResponse

	err = decoder.Decode(&singleEmailReqResp)
	if err != nil {
		return false, err
	}

	if singleEmailReqResp.Success == false {
		return false, fmt.Errorf("Unable to check email validity: %#v", singleEmailReqResp.ErrorMsg)
	}

	if singleEmailReqResp.Result == 0 {
		return true, nil
	}

	return false, nil
}
