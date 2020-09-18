package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	restErrors "github.com/nguyenphucthienan/book-store-utils-go/errors"
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

func AuthenticateRequest(request *http.Request) restErrors.RestError {
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
		if err.Status() == http.StatusNotFound {
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

func getAccessToken(accessTokenId string) (*accessToken, restErrors.RestError) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_tokens/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, restErrors.NewInternalServerError(
			"Invalid rest client response when trying to get access token", errors.New("network timeout"))
	}

	if response.StatusCode > 299 {
		restErr, err := restErrors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, restErrors.NewInternalServerError("Invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}

	var token accessToken
	if err := json.Unmarshal(response.Bytes(), &token); err != nil {
		return nil, restErrors.NewInternalServerError("Error when trying to unmarshal access token response", err)
	}

	return &token, nil
}
