// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"

	"github.com/pilot-protocol/common/reqsig"
)

// cmdSignRequest asks the daemon to sign a request-signature envelope
// (common/reqsig) for a consuming service. The daemon constructs the
// envelope itself (its own address, current timestamp, fresh nonce) — the
// CLI only supplies the audience and the body hash. Exactly one body
// source is required:
//
//	pilotctl sign-request --audience svc.example.io --body-file req.json
//	pilotctl sign-request --audience svc.example.io --body '{"q":"x"}'
//	pilotctl sign-request --audience svc.example.io --body-hash <64 hex>
func cmdSignRequest(args []string) {
	flags, _ := parseFlags(args)
	audience := flagString(flags, "audience", "")
	if audience == "" {
		fatalCode("invalid_argument", "usage: pilotctl sign-request --audience <a> (--body-file <f> | --body-hash <64hex> | --body '<string>')")
	}

	bodyHash := flagString(flags, "body-hash", "")
	bodyFile := flagString(flags, "body-file", "")
	body, bodySet := flags["body"]
	sources := 0
	if bodyHash != "" {
		sources++
	}
	if bodyFile != "" {
		sources++
	}
	if bodySet {
		sources++
	}
	if sources != 1 {
		fatalCode("invalid_argument", "sign-request: exactly one of --body-file, --body-hash, --body is required")
	}
	switch {
	case bodyFile != "":
		data, err := os.ReadFile(bodyFile)
		if err != nil {
			fatalCode("invalid_argument", "sign-request: read %s: %v", bodyFile, err)
		}
		bodyHash = reqsig.HashBody(data)
	case bodySet:
		bodyHash = reqsig.HashBody([]byte(body))
	}

	d := connectDriver()
	defer d.Close()
	resp, err := d.SignEnvelope(audience, bodyHash)
	if err != nil {
		fatalCode("connection_failed", "sign-request: %v", err)
	}
	output(map[string]interface{}{
		"envelope":  resp["envelope"],
		"signature": resp["signature"],
		"address":   resp["address"],
	})
}

// cmdVerifyRequest checks a reqsig envelope + signature via the daemon,
// which resolves the claimed node's key from its local cache first and the
// registry on miss. Prints the daemon's reply; exits 1 when the daemon
// reports valid:false.
func cmdVerifyRequest(args []string) {
	flags, _ := parseFlags(args)
	envelope := flagString(flags, "envelope", "")
	sig := flagString(flags, "signature", "")
	if envelope == "" || sig == "" {
		fatalCode("invalid_argument", "usage: pilotctl verify-request --envelope '<canonical>' --signature '<b64>' [--standing] [--max-skew <secs>]")
	}
	standing := flagBool(flags, "standing")
	maxSkew := flagInt(flags, "max-skew", 0)
	if maxSkew < 0 {
		fatalCode("invalid_argument", "verify-request: --max-skew must be >= 0")
	}

	d := connectDriver()
	defer d.Close()
	resp, err := d.VerifyEnvelopeMaxSkew(envelope, sig, standing, uint32(maxSkew))
	if err != nil {
		fatalCode("connection_failed", "verify-request: %v", err)
	}
	output(resp)
	if valid, _ := resp["valid"].(bool); !valid {
		os.Exit(1)
	}
}
