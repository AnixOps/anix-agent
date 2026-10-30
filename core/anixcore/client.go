package anixcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync/atomic"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

const requestTimeout = 15 * time.Second

// apiUser is a user of the anixcore management API.
type apiUser struct {
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Flow     string `json:"flow,omitempty"`
	// iWAN fixed tunnel address.
	Address string `json:"address,omitempty"`
	// SpeedLimit is Mbit/s per direction, DeviceLimit the most client IPs
	// online at once; 0 for none. Sent only to a kernel with the
	// `user_limits` feature.
	SpeedLimit  int `json:"speed_limit,omitempty"`
	DeviceLimit int `json:"device_limit,omitempty"`
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
	// userLimits is whether the kernel takes user speed and device limits,
	// from the features of its last status answer.
	userLimits atomic.Bool
	// blockRules is whether the kernel takes block rules (PUT /v1/rules).
	blockRules atomic.Bool
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
	var status struct {
		Features []string `json:"features"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &status); err != nil {
		return err
	}
	c.userLimits.Store(slices.Contains(status.Features, "user_limits"))
	c.blockRules.Store(slices.Contains(status.Features, "block_rules"))
	return nil
}

// forKernel drops what the kernel does not take from users.
func (c *client) forKernel(users []apiUser) []apiUser {
	if c.userLimits.Load() {
		return users
	}
	out := make([]apiUser, len(users))
	for i, user := range users {
		user.SpeedLimit, user.DeviceLimit = 0, 0
		out[i] = user
	}
	return out
}

// wireTagPattern is the inbound tags anixcore accepts.
var wireTagPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// wireTag answers the anixcore tag of an Agent tag. A node's tag
// ("[<api host>]-vless:62") has characters anixcore refuses, so a tag
// outside wireTagPattern is sent as node-<sha256 prefix>; a valid tag
// (a port forward's) is sent as it is.
func wireTag(tag string) string {
	if wireTagPattern.MatchString(tag) {
		return tag
	}
	sum := sha256.Sum256([]byte(tag))
	return "node-" + hex.EncodeToString(sum[:12])
}

// inboundPath is the escaped path segment of tag's inbound.
func inboundPath(tag string) string {
	return url.PathEscape(wireTag(tag))
}

func (c *client) addInbound(ctx context.Context, inbound map[string]any) error {
	return c.do(ctx, http.MethodPost, "/v1/inbounds", inbound, nil)
}

func (c *client) removeInbound(ctx context.Context, tag string) error {
	return c.do(ctx, http.MethodDelete, "/v1/inbounds/"+inboundPath(tag), nil, nil)
}

func (c *client) addUsers(ctx context.Context, tag string, users []apiUser) error {
	body := map[string]any{"users": c.forKernel(users)}
	return c.do(ctx, http.MethodPost, "/v1/inbounds/"+inboundPath(tag)+"/users", body, nil)
}

func (c *client) removeUsers(ctx context.Context, tag string, names []string) error {
	body := map[string]any{"names": names}
	return c.do(ctx, http.MethodPost, "/v1/inbounds/"+inboundPath(tag)+"/users/remove", body, nil)
}

func (c *client) traffic(ctx context.Context, tag string, reset bool) ([]apiTraffic, error) {
	path := "/v1/inbounds/" + inboundPath(tag) + "/traffic"
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

func (c *client) putRules(ctx context.Context, rules rulesConfig) error {
	return c.do(ctx, http.MethodPut, "/v1/rules", rules, nil)
}

func (c *client) putEgress(ctx context.Context, config *panel.EgressConfig) error {
	return c.do(ctx, http.MethodPut, "/v1/egress", config, nil)
}

func (c *client) putNetwork(ctx context.Context, plan json.RawMessage, out any) error {
	return c.do(ctx, http.MethodPut, "/v1/network", plan, out)
}

func (c *client) getNetwork(ctx context.Context, out any) error {
	return c.do(ctx, http.MethodGet, "/v1/network", nil, out)
}

func (c *client) online(ctx context.Context, tag string) ([]apiOnline, error) {
	var answer struct {
		Online []apiOnline `json:"online"`
	}
	path := "/v1/inbounds/" + inboundPath(tag) + "/online"
	if err := c.do(ctx, http.MethodGet, path, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Online, nil
}
