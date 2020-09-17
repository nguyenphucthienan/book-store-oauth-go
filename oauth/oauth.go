package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/nguyenphucthienan/book-store-oauth-go/utils/errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080/api",
		Timeout: 100 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	token, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", token.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", token.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestError) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_tokens/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Invalid rest client response when trying to get access token")
	}

	if response.StatusCode > 299 {
		restErr, err := errors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface when trying to get access token")
		}
		return nil, restErr
	}

	var token accessToken
	if err := json.Unmarshal(response.Bytes(), &token); err != nil {
		return nil, errors.NewInternalServerError("Error when trying to unmarshal access token response")
	}
	return &token, nil
}
