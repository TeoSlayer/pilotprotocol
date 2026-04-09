package responder

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sharedHTTPClient is used for all service calls.
var sharedHTTPClient = &http.Client{Timeout: 30 * time.Second}

// Dispatch validates a CommandRequest against cfg, calls the backing service,
// and returns the response body.
//
// The full cycle is:
//  1. Look up command in config.
//  2. Match body against arg_regex; extract named capture groups as query params.
//  3. Build the service URL and issue an HTTP GET.
//  4. Return the response body on 2xx, or an error otherwise.
func Dispatch(cfg *Config, req *CommandRequest) (string, error) {
	endpoint, ok := cfg.EndpointByName(req.Command)
	if !ok {
		return "", &UnknownCommandError{
			Command:   req.Command,
			Available: cfg.CommandList(),
		}
	}

	params, err := ExtractParams(endpoint, req.Body)
	if err != nil {
		return "", err
	}

	serviceURL, err := BuildURL(endpoint.Link, params)
	if err != nil {
		return "", fmt.Errorf("build service URL: %w", err)
	}

	resp, err := sharedHTTPClient.Get(serviceURL)
	if err != nil {
		return "", fmt.Errorf("service call to %s: %w", serviceURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read service response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("service returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return string(body), nil
}

// UnknownCommandError is returned when the requested command is not in the config.
type UnknownCommandError struct {
	Command   string
	Available string
}

func (e *UnknownCommandError) Error() string {
	return fmt.Sprintf(
		"Unavailable command %q. Here is a list of available commands and their structure:\n%s",
		e.Command, e.Available,
	)
}

// ExtractParams applies the endpoint's arg_regex to body and returns a map of
// named capture groups → values that will be appended as query parameters.
//
// If the endpoint has no arg_regex, no query params are added (bare link is used).
// Returns an error when a regex is configured but the body does not match.
func ExtractParams(endpoint *EndpointConfig, body string) (map[string]string, error) {
	re := endpoint.Compiled()
	if re == nil {
		return nil, nil
	}

	body = strings.TrimSpace(body)
	match := re.FindStringSubmatch(body)
	if match == nil {
		return nil, fmt.Errorf(
			"message body %q does not match the expected format for command %q\nExpected pattern: %s",
			body, endpoint.Name, endpoint.ArgRegex,
		)
	}

	params := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if name != "" && i < len(match) && match[i] != "" {
			params[name] = match[i]
		}
	}
	return params, nil
}

// BuildURL appends params as query string values to base.
func BuildURL(base string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return base, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base URL %q: %w", base, err)
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
