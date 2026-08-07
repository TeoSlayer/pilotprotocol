// SPDX-License-Identifier: AGPL-3.0-or-later

package decisionhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pilot-protocol/common/decision"
)

const EvaluatorAttestationPath = "/v1/evaluator-attestation"

func (client *Client) EvaluatorAttestation(ctx context.Context) (decision.EvaluatorAttestation, error) {
	if client == nil || client.endpoint == nil || client.httpClient == nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: client is not initialized")
	}
	endpoint := *client.endpoint
	endpoint.Path = EvaluatorAttestationPath
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: build evaluator attestation request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: evaluator attestation request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: read evaluator attestation: %w", err)
	}
	if int64(len(body)) > client.maxResponseBytes {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: evaluator attestation exceeds %d bytes", client.maxResponseBytes)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: evaluator attestation returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var attestation decision.EvaluatorAttestation
	if err := decoder.Decode(&attestation); err != nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: decode evaluator attestation: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return decision.EvaluatorAttestation{}, err
	}
	if err := attestation.Validate(); err != nil {
		return decision.EvaluatorAttestation{}, fmt.Errorf("decisionhttp: invalid evaluator attestation: %w", err)
	}
	return attestation, nil
}

func (client *Client) EvaluatorOrigin() (string, error) {
	if client == nil || client.endpoint == nil {
		return "", fmt.Errorf("decisionhttp: client is not initialized")
	}
	return canonicalClientOrigin(client.endpoint)
}

func canonicalClientOrigin(endpoint *url.URL) (string, error) {
	if endpoint == nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return "", fmt.Errorf("decisionhttp: evaluator endpoint is invalid")
	}
	return strings.ToLower(endpoint.Scheme) + "://" + strings.ToLower(endpoint.Host), nil
}
