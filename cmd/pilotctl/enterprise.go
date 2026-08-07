// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authority"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/authorityhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionhttp"
	"github.com/pilot-protocol/pilotprotocol/internal/managedsdk/decisionpolicy"
)

const enterpriseHelpText = `Usage: pilotctl enterprise <adopt|status|dashboard-url|trust|policy|mandate|receipt|workflow|hook> [flags]

Read the signed enterprise control state from an authority, or produce its
read-only dashboard URL. The policy subcommands submit already-signed
artifacts; this command never creates tenant authority signatures.

Flags:
  --endpoint <URL>      authority base URL (HTTPS; HTTP is allowed only for loopback)
  --tenant <tenant>     tenant identifier
  --client-cert <path>  operator TLS client certificate PEM (API commands)
  --client-key <path>   owner-only operator TLS private-key PEM (API commands)
  --server-ca <path>    PEM CA bundle used to verify the authority (API commands)
  --bearer-token-env <name>  environment variable holding an OIDC access token (API commands)

Examples:
  pilotctl enterprise status --endpoint https://authority.example --tenant acme \
    --client-cert operator.pem --client-key operator-key.pem --server-ca authority-ca.pem
  pilotctl enterprise dashboard-url --endpoint https://authority.example --tenant acme
  pilotctl enterprise trust publish --bundle root-signed-trust.json --endpoint https://authority.example --tenant acme
  pilotctl enterprise policy status --endpoint https://authority.example --tenant acme --id rollout-42
  pilotctl enterprise mandate publish --bundle agent-mandates.json --endpoint https://authority.example --tenant acme
  pilotctl enterprise receipt list --limit 50 --endpoint https://authority.example --tenant acme
  pilotctl enterprise workflow cancel --id transaction-42 --reason "duplicate payment" --endpoint https://authority.example --tenant acme

Policy lifecycle:
  pilotctl enterprise policy simulate --publication <file> --bundle <file> (--intents <file> | --inputs <file>) [flags]
  pilotctl enterprise policy publish --publication <file> --bundle <file> [flags]
  pilotctl enterprise policy activate --activation <file> [flags]
  pilotctl enterprise policy status --id <publication-id> [flags]

Trust lifecycle:
  pilotctl enterprise trust publish --bundle <file> [flags]

Mandate lifecycle:
  pilotctl enterprise mandate publish --bundle <file> [flags]

Evidence:
  pilotctl enterprise receipt list [--limit <1-1000>] [flags]

Workflow operations:
  pilotctl enterprise workflow list [--limit <1-1000>] [flags]
  pilotctl enterprise workflow status --id <transaction-id> [flags]
  pilotctl enterprise workflow cancel --id <transaction-id> --reason <reason> [flags]

External agent hooks (JSON request on stdin; invoked by an optional harness adapter):
  pilotctl --json enterprise hook pre [--control <enterprise-control.json>]
  pilotctl --json enterprise hook post [--control <enterprise-control.json>]

One-time managed adoption (a core Pilot operation; no MCP server is required):
  PILOT_ENROLLMENT_TOKEN=... pilotctl --json enterprise adopt --endpoint https://management.example
`

// cmdEnterprise is a read-only operator surface over the authority's signed
// management view. Policy publication and activation remain separate signed
// operations; this CLI deliberately does not turn a terminal into a bypass.
func cmdEnterprise(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: pilotctl enterprise adopt | status | dashboard-url | trust | policy | mandate | receipt | workflow", "missing enterprise subcommand")
	}
	switch args[0] {
	case "adopt":
		cmdEnterpriseAdopt(args[1:])
	case "status":
		cmdEnterpriseStatus(args[1:])
	case "dashboard-url":
		cmdEnterpriseDashboardURL(args[1:])
	case "trust":
		cmdEnterpriseTrust(args[1:])
	case "policy":
		cmdEnterprisePolicy(args[1:])
	case "mandate":
		cmdEnterpriseMandate(args[1:])
	case "receipt":
		cmdEnterpriseReceipt(args[1:])
	case "workflow":
		cmdEnterpriseWorkflow(args[1:])
	case "hook":
		cmdEnterpriseHook(args[1:])
	default:
		fatalHint("invalid_argument", "available: adopt, status, dashboard-url, trust, policy, mandate, receipt, workflow, hook", "unknown enterprise subcommand: %s", args[0])
	}
}

type enterpriseFlags struct {
	endpoint       string
	tenantID       string
	clientCert     string
	clientKey      string
	serverCA       string
	bearerTokenEnv string
}

func enterpriseFlagSet(name string, result *enterpriseFlags) *flag.FlagSet {
	flags := flag.NewFlagSet("enterprise "+name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&result.endpoint, "endpoint", "", "authority base URL")
	flags.StringVar(&result.tenantID, "tenant", "", "tenant ID")
	flags.StringVar(&result.clientCert, "client-cert", "", "operator mTLS client certificate PEM")
	flags.StringVar(&result.clientKey, "client-key", "", "operator mTLS client private-key PEM")
	flags.StringVar(&result.serverCA, "server-ca", "", "optional PEM CA bundle for authority TLS")
	flags.StringVar(&result.bearerTokenEnv, "bearer-token-env", "", "environment variable holding an OIDC access token")
	return flags
}

func parseEnterpriseFlagSet(name string, flags *flag.FlagSet, result *enterpriseFlags, args []string) enterpriseFlags {
	if err := flags.Parse(args); err != nil {
		fatalCode("invalid_argument", "enterprise %s flags: %v", name, err)
	}
	if flags.NArg() != 0 {
		fatalCode("invalid_argument", "enterprise %s accepts flags only", name)
	}
	if strings.TrimSpace(result.endpoint) == "" || strings.TrimSpace(result.tenantID) == "" {
		fatalCode("invalid_argument", "enterprise %s requires --endpoint and --tenant", name)
	}
	if (result.clientCert == "") != (result.clientKey == "") {
		fatalCode("invalid_argument", "enterprise %s requires --client-cert and --client-key together", name)
	}
	if result.bearerTokenEnv != "" && !enterpriseEnvironmentName(result.bearerTokenEnv) {
		fatalCode("invalid_argument", "enterprise %s bearer-token-env must be an environment variable name", name)
	}
	return *result
}

func parseEnterpriseFlags(name string, args []string) enterpriseFlags {
	result := enterpriseFlags{}
	return parseEnterpriseFlagSet(name, enterpriseFlagSet(name, &result), &result, args)
}

func cmdEnterpriseStatus(args []string) {
	options := parseEnterpriseFlags("status", args)
	httpClient, err := enterpriseHTTPClient(options)
	if err != nil {
		fatalCode("invalid_argument", "enterprise status TLS configuration: %v", err)
	}
	client, err := authorityhttp.New(options.endpoint, httpClient)
	if err != nil {
		fatalCode("invalid_argument", "enterprise status endpoint: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	state, err := client.ManagementState(ctx, options.tenantID)
	if err != nil {
		fatalCode("unavailable", "enterprise status: %v", err)
	}
	output(map[string]interface{}{
		"tenant_id":        state.Trust.TenantID,
		"trust_revision":   state.Trust.Revision,
		"policy_revision":  state.ActivePolicy.Revision,
		"revocation_epoch": state.Trust.RevocationEpoch,
		"rollouts":         state.Rollouts,
		"mandate_bundles":  state.MandateBundles,
		"recent_workflows": state.RecentWorkflows,
		"recent_receipts":  state.RecentReceipts,
		"usage_export":     state.UsageExport,
	})
}

func cmdEnterpriseDashboardURL(args []string) {
	options := parseEnterpriseFlags("dashboard-url", args)
	if options.clientCert != "" || options.clientKey != "" || options.serverCA != "" || options.bearerTokenEnv != "" {
		fatalCode("invalid_argument", "enterprise dashboard-url only prints a link; configure browser mTLS and trust directly")
	}
	if _, err := authorityhttp.New(options.endpoint, nil); err != nil {
		fatalCode("invalid_argument", "enterprise dashboard endpoint: %v", err)
	}
	endpoint, err := url.Parse(options.endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		fatalCode("invalid_argument", "enterprise dashboard endpoint is invalid")
	}
	endpoint.Path = "/v1/manage/dashboard"
	query := endpoint.Query()
	query.Set("tenant_id", options.tenantID)
	endpoint.RawQuery = query.Encode()
	output(map[string]interface{}{"dashboard_url": endpoint.String(), "note": "The browser must present the configured operator mTLS certificate for remote access."})
}

func cmdEnterpriseTrust(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: publish", "missing enterprise trust subcommand")
	}
	if args[0] != "publish" {
		fatalHint("invalid_argument", "available: publish", "unknown enterprise trust subcommand: %s", args[0])
	}
	base := enterpriseFlags{}
	bundlePath := ""
	flags := enterpriseFlagSet("trust publish", &base)
	flags.StringVar(&bundlePath, "bundle", "", "root-signed trust bundle JSON")
	options := parseEnterpriseFlagSet("trust publish", flags, &base, args[1:])
	if strings.TrimSpace(bundlePath) == "" {
		fatalCode("invalid_argument", "enterprise trust publish requires --bundle")
	}
	bundle := readEnterpriseJSON[authority.TrustBundle](bundlePath, "trust bundle")
	if bundle.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise trust bundle tenant does not match --tenant")
	}
	client := enterpriseManagementClient(options, "trust publish")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	published, err := client.PublishTrust(ctx, bundle)
	if err != nil {
		fatalCode("unavailable", "enterprise trust publish: %v", err)
	}
	output(map[string]interface{}{"trust": published})
}

type enterprisePolicyFlags struct {
	publicationPath string
	bundlePath      string
	activationPath  string
	intentsPath     string
	inputsPath      string
	publicationID   string
}

func parseEnterprisePolicyFlags(name string, args []string) (enterpriseFlags, enterprisePolicyFlags) {
	base := enterpriseFlags{}
	policy := enterprisePolicyFlags{}
	flags := enterpriseFlagSet("policy "+name, &base)
	flags.StringVar(&policy.publicationPath, "publication", "", "signed policy publication JSON")
	flags.StringVar(&policy.bundlePath, "bundle", "", "signed policy bundle JSON")
	flags.StringVar(&policy.activationPath, "activation", "", "signed policy activation JSON")
	flags.StringVar(&policy.intentsPath, "intents", "", "signed simulation intent array JSON")
	flags.StringVar(&policy.inputsPath, "inputs", "", "signed simulation input array JSON (supports disclosure bindings)")
	flags.StringVar(&policy.publicationID, "id", "", "policy publication ID")
	return parseEnterpriseFlagSet("policy "+name, flags, &base, args), policy
}

func cmdEnterprisePolicy(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: publish, simulate, activate, status", "missing enterprise policy subcommand")
	}
	switch args[0] {
	case "publish":
		cmdEnterprisePolicyPublish(args[1:])
	case "simulate":
		cmdEnterprisePolicySimulate(args[1:])
	case "activate":
		cmdEnterprisePolicyActivate(args[1:])
	case "status":
		cmdEnterprisePolicyStatus(args[1:])
	default:
		fatalHint("invalid_argument", "available: publish, simulate, activate, status", "unknown enterprise policy subcommand: %s", args[0])
	}
}

func cmdEnterprisePolicyPublish(args []string) {
	options, policy := parseEnterprisePolicyFlags("publish", args)
	if policy.publicationPath == "" || policy.bundlePath == "" {
		fatalCode("invalid_argument", "enterprise policy publish requires --publication and --bundle")
	}
	publication := readEnterpriseJSON[authority.PolicyPublication](policy.publicationPath, "policy publication")
	bundle := readEnterpriseJSON[authority.PolicyBundle](policy.bundlePath, "policy bundle")
	if publication.TenantID != options.tenantID || bundle.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise policy publish artifact tenant does not match --tenant")
	}
	client := enterpriseManagementClient(options, "publish")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := client.Publish(ctx, publication, bundle)
	if err != nil {
		fatalCode("unavailable", "enterprise policy publish: %v", err)
	}
	output(map[string]interface{}{"rollout": status})
}

func cmdEnterprisePolicySimulate(args []string) {
	options, policy := parseEnterprisePolicyFlags("simulate", args)
	if policy.publicationPath == "" || policy.bundlePath == "" || (policy.intentsPath == "" && policy.inputsPath == "") || (policy.intentsPath != "" && policy.inputsPath != "") {
		fatalCode("invalid_argument", "enterprise policy simulate requires --publication, --bundle, and exactly one of --intents or --inputs")
	}
	publication := readEnterpriseJSON[authority.PolicyPublication](policy.publicationPath, "policy publication")
	bundle := readEnterpriseJSON[authority.PolicyBundle](policy.bundlePath, "policy bundle")
	request := authorityhttp.SimulationRequest{Publication: publication, Bundle: bundle}
	if policy.inputsPath != "" {
		request.Inputs = readEnterpriseJSON[[]decisionpolicy.SimulationInput](policy.inputsPath, "simulation inputs")
	} else {
		request.Intents = readEnterpriseJSON[[]decision.Intent](policy.intentsPath, "simulation intents")
	}
	if publication.TenantID != options.tenantID || bundle.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise policy simulation artifact tenant does not match --tenant")
	}
	client := enterpriseManagementClient(options, "simulate")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	simulation, err := client.Simulate(ctx, request)
	if err != nil {
		fatalCode("unavailable", "enterprise policy simulate: %v", err)
	}
	output(map[string]interface{}{"simulation": simulation})
}

func cmdEnterprisePolicyActivate(args []string) {
	options, policy := parseEnterprisePolicyFlags("activate", args)
	if policy.activationPath == "" {
		fatalCode("invalid_argument", "enterprise policy activate requires --activation")
	}
	activation := readEnterpriseJSON[authority.PolicyActivation](policy.activationPath, "policy activation")
	if activation.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise policy activation tenant does not match --tenant")
	}
	client := enterpriseManagementClient(options, "activate")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := client.Activate(ctx, activation)
	if err != nil {
		fatalCode("unavailable", "enterprise policy activate: %v", err)
	}
	output(map[string]interface{}{"rollout": status})
}

func cmdEnterprisePolicyStatus(args []string) {
	options, policy := parseEnterprisePolicyFlags("status", args)
	if strings.TrimSpace(policy.publicationID) == "" {
		fatalCode("invalid_argument", "enterprise policy status requires --id")
	}
	client := enterpriseManagementClient(options, "status")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := client.Status(ctx, policy.publicationID)
	if err != nil {
		fatalCode("unavailable", "enterprise policy status: %v", err)
	}
	if status.Publication.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise policy status tenant binding mismatch")
	}
	output(map[string]interface{}{"rollout": status})
}

func cmdEnterpriseMandate(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: publish", "missing enterprise mandate subcommand")
	}
	if args[0] != "publish" {
		fatalHint("invalid_argument", "available: publish", "unknown enterprise mandate subcommand: %s", args[0])
	}
	base := enterpriseFlags{}
	bundlePath := ""
	flags := enterpriseFlagSet("mandate publish", &base)
	flags.StringVar(&bundlePath, "bundle", "", "signed mandate bundle JSON")
	options := parseEnterpriseFlagSet("mandate publish", flags, &base, args[1:])
	if strings.TrimSpace(bundlePath) == "" {
		fatalCode("invalid_argument", "enterprise mandate publish requires --bundle")
	}
	bundle := readEnterpriseJSON[decision.MandateBundle](bundlePath, "mandate bundle")
	if bundle.TenantID != options.tenantID {
		fatalCode("invalid_argument", "enterprise mandate bundle tenant does not match --tenant")
	}
	client := enterpriseManagementClient(options, "mandate publish")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	published, err := client.PublishMandateBundle(ctx, bundle)
	if err != nil {
		fatalCode("unavailable", "enterprise mandate publish: %v", err)
	}
	output(map[string]interface{}{"mandate_bundle": published})
}

func cmdEnterpriseReceipt(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: list", "missing enterprise receipt subcommand")
	}
	if args[0] != "list" {
		fatalHint("invalid_argument", "available: list", "unknown enterprise receipt subcommand: %s", args[0])
	}
	base := enterpriseFlags{}
	limit := 100
	flags := enterpriseFlagSet("receipt list", &base)
	flags.IntVar(&limit, "limit", 100, "maximum receipts to return (1-1000)")
	options := parseEnterpriseFlagSet("receipt list", flags, &base, args[1:])
	if limit < 1 || limit > 1000 {
		fatalCode("invalid_argument", "enterprise receipt list --limit must be 1-1000")
	}
	client := enterpriseManagementClient(options, "receipt list")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	receipts, err := client.Receipts(ctx, options.tenantID, limit)
	if err != nil {
		fatalCode("unavailable", "enterprise receipt list: %v", err)
	}
	output(map[string]interface{}{"receipts": receipts})
}

type enterpriseWorkflowFlags struct {
	transactionID string
	reason        string
	limit         int
}

func parseEnterpriseWorkflowFlags(name string, args []string) (enterpriseFlags, enterpriseWorkflowFlags) {
	base := enterpriseFlags{}
	workflow := enterpriseWorkflowFlags{}
	flags := enterpriseFlagSet("workflow "+name, &base)
	flags.StringVar(&workflow.transactionID, "id", "", "approval workflow transaction ID")
	flags.StringVar(&workflow.reason, "reason", "", "non-empty cancellation reason")
	flags.IntVar(&workflow.limit, "limit", 100, "maximum workflows to return (1-1000)")
	return parseEnterpriseFlagSet("workflow "+name, flags, &base, args), workflow
}

// cmdEnterpriseWorkflow is the operator-facing workflow surface. The
// authority mTLS boundary and the authority's signed cancellation artifact
// remain the actual control points; this CLI only carries their requests.
func cmdEnterpriseWorkflow(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument", "available: list, status, cancel", "missing enterprise workflow subcommand")
	}
	switch args[0] {
	case "list":
		options, workflow := parseEnterpriseWorkflowFlags("list", args[1:])
		if workflow.limit < 1 || workflow.limit > 1000 {
			fatalCode("invalid_argument", "enterprise workflow list --limit must be 1-1000")
		}
		client := enterpriseWorkflowClient(options, "workflow list")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		records, err := client.ManagementWorkflows(ctx, options.tenantID, workflow.limit)
		if err != nil {
			fatalCode("unavailable", "enterprise workflow list: %v", err)
		}
		output(map[string]interface{}{"workflows": records})
	case "status":
		options, workflow := parseEnterpriseWorkflowFlags("status", args[1:])
		if strings.TrimSpace(workflow.transactionID) == "" {
			fatalCode("invalid_argument", "enterprise workflow status requires --id")
		}
		client := enterpriseWorkflowClient(options, "workflow status")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		record, err := client.ManagementWorkflowStatus(ctx, workflow.transactionID)
		if err != nil {
			fatalCode("unavailable", "enterprise workflow status: %v", err)
		}
		if record.Transaction.TenantID != options.tenantID {
			fatalCode("invalid_argument", "enterprise workflow status tenant binding mismatch")
		}
		output(map[string]interface{}{"workflow": record})
	case "cancel":
		options, workflow := parseEnterpriseWorkflowFlags("cancel", args[1:])
		if strings.TrimSpace(workflow.transactionID) == "" || strings.TrimSpace(workflow.reason) == "" {
			fatalCode("invalid_argument", "enterprise workflow cancel requires --id and --reason")
		}
		client := enterpriseWorkflowClient(options, "workflow cancel")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		record, err := client.CancelWorkflow(ctx, workflow.transactionID, workflow.reason)
		if err != nil {
			fatalCode("unavailable", "enterprise workflow cancel: %v", err)
		}
		if record.Transaction.TenantID != options.tenantID {
			fatalCode("invalid_argument", "enterprise workflow cancellation tenant binding mismatch")
		}
		output(map[string]interface{}{"workflow": record})
	default:
		fatalHint("invalid_argument", "available: list, status, cancel", "unknown enterprise workflow subcommand: %s", args[0])
	}
}

func enterpriseManagementClient(options enterpriseFlags, operation string) *authorityhttp.Client {
	httpClient, err := enterpriseHTTPClient(options)
	if err != nil {
		fatalCode("invalid_argument", "enterprise %s TLS configuration: %v", operation, err)
	}
	client, err := authorityhttp.New(options.endpoint, httpClient)
	if err != nil {
		fatalCode("invalid_argument", "enterprise %s endpoint: %v", operation, err)
	}
	return client
}

func enterpriseWorkflowClient(options enterpriseFlags, operation string) *decisionhttp.Client {
	httpClient, err := enterpriseHTTPClient(options)
	if err != nil {
		fatalCode("invalid_argument", "enterprise %s TLS configuration: %v", operation, err)
	}
	client, err := decisionhttp.New(options.endpoint, decisionhttp.WithHTTPClient(httpClient))
	if err != nil {
		fatalCode("invalid_argument", "enterprise %s endpoint: %v", operation, err)
	}
	return client
}

func readEnterpriseJSON[T any](path, label string) T {
	if err := enterpriseCertificateFile(path); err != nil {
		fatalCode("invalid_argument", "%s: %v", label, err)
	}
	// #nosec G304 -- path is explicit operator input and enterpriseCertificateFile rejects unsafe file types and permissions first.
	file, err := os.Open(path)
	if err != nil {
		fatalCode("invalid_argument", "%s: %v", label, err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, (2<<20)+1))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		fatalCode("invalid_argument", "%s: %v", label, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		fatalCode("invalid_argument", "%s contains trailing data", label)
	}
	return value
}

func enterpriseHTTPClient(options enterpriseFlags) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if options.clientCert != "" {
		if err := enterpriseCertificateFile(options.clientCert); err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		if err := enterpriseSecretFile(options.clientKey); err != nil {
			return nil, fmt.Errorf("client key: %w", err)
		}
		certificate, err := tls.LoadX509KeyPair(options.clientCert, options.clientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	if options.serverCA != "" {
		if err := enterpriseCertificateFile(options.serverCA); err != nil {
			return nil, fmt.Errorf("server CA: %w", err)
		}
		contents, err := os.ReadFile(options.serverCA)
		if err != nil {
			return nil, fmt.Errorf("server CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(contents) {
			return nil, fmt.Errorf("server CA contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	var roundTripper http.RoundTripper = transport
	if options.bearerTokenEnv != "" {
		token := strings.TrimSpace(os.Getenv(options.bearerTokenEnv))
		if token == "" || len(token) > 16<<10 || strings.ContainsAny(token, " \t\r\n") {
			return nil, fmt.Errorf("bearer token environment variable %q is empty or invalid", options.bearerTokenEnv)
		}
		roundTripper = enterpriseBearerTransport{next: transport, token: token}
	}
	return &http.Client{Transport: roundTripper, Timeout: 15 * time.Second}, nil
}

type enterpriseBearerTransport struct {
	next  http.RoundTripper
	token string
}

func (transport enterpriseBearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, fmt.Errorf("enterprise bearer transport: request is nil")
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+transport.token)
	return transport.next.RoundTrip(clone)
}

func enterpriseEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if !(character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			(index > 0 && character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func enterpriseCertificateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a regular file")
	}
	return nil
}

func enterpriseSecretFile(path string) error {
	if err := enterpriseCertificateFile(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("must be owner-only (mode 0600 or stricter)")
	}
	return nil
}
