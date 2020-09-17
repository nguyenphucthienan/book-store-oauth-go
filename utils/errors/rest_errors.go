package errors

import (
	"encoding/json"
	"errors"
	"net/http"
)

type RestError struct {
	Message string `json:"message"`
	Status  int    `json:"code"`
	Error   string `json:"errors"`
}

func NewBadRequestError(message string) *RestError {
	return &RestError{
		Message: message,
		Status:  http.StatusBadRequest,
		Error:   "bad_request",
	}
}

func NewNotFoundError(message string) *RestError {
	return &RestError{
		Message: message,
		Status:  http.StatusNotFound,
		Error:   "not_found",
	}
}

func NewInternalServerError(message string) *RestError {
	return &RestError{
		Message: message,
		Status:  http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}

func NewRestErrorFromBytes(bytes []byte) (*RestError, error) {
	var restErr RestError
	if err := json.Unmarshal(bytes, &restErr); err != nil {
		return nil, errors.New("invalid json")
	}
	return &restErr, nil
}
