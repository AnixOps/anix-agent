package anixcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const requestTimeout = 15 * time.Second

// apiUser is a user of the anixcore management API.
type apiUser struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
}

type apiTraffic struct {
	Name string `json:"name"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type apiOnline struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Connections int    `json:"connections"`
}

// apiError is an error answer of the management API.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("anixcore api: %d %s", e.Status, e.Message)
}

func isStatus(err error, status int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.Status == status
}

// client talks to the anixcore management API: HTTP/1.1 with JSON bodies,
// authorized by a bearer token.
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(address, token string) *client {
	return &client{
		base:  "http://" + address,
		token: token,
		http: &http.Client{
			Timeout: requestTimeout,
			// The API answers one request per connection.
			Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil},
		},
	}
}

func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return err
	}
	if response.StatusCode/100 != 2 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(answer, &failure)
		return &apiError{Status: response.StatusCode, Message: failure.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(answer, out)
}

func (c *client) status(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/status", nil, nil)
}

func (c *client) addInbound(ctx context.Context, inbound map[string]any) error {
	return c.do(ctx, http.MethodPost, "/v1/inbounds", inbound, nil)
}

func (c *client) removeInbound(ctx context.Context, tag string) error {
	return c.do(ctx, http.MethodDelete, "/v1/inbounds/"+url.PathEscape(tag), nil, nil)
}

func (c *client) addUsers(ctx context.Context, tag string, users []apiUser) error {
	body := map[string]any{"users": users}
	return c.do(ctx, http.MethodPost, "/v1/inbounds/"+url.PathEscape(tag)+"/users", body, nil)
}

func (c *client) removeUsers(ctx context.Context, tag string, names []string) error {
	body := map[string]any{"names": names}
	return c.do(ctx, http.MethodPost, "/v1/inbounds/"+url.PathEscape(tag)+"/users/remove", body, nil)
}

func (c *client) traffic(ctx context.Context, tag string, reset bool) ([]apiTraffic, error) {
	path := "/v1/inbounds/" + url.PathEscape(tag) + "/traffic"
	if reset {
		path += "?reset=true"
	}
	var answer struct {
		Traffic []apiTraffic `json:"traffic"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Traffic, nil
}

func (c *client) online(ctx context.Context, tag string) ([]apiOnline, error) {
	var answer struct {
		Online []apiOnline `json:"online"`
	}
	path := "/v1/inbounds/" + url.PathEscape(tag) + "/online"
	if err := c.do(ctx, http.MethodGet, path, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Online, nil
}
