// smoke-pay-driver — generic IPC driver for the smoke test.
//
// Talks to any installed app over its unix socket using only
// app-store/pkg/ipc. Deliberately does NOT import wallet types — the
// point of the app store is that apps are dynamic, discovered through
// their manifest's `exposes` list. A third-party tool inspecting a
// fresh install has no compile-time knowledge of the methods. JSON
// shapes here mirror what the wallet manifest documents (and what
// pilotctl appstore call would send).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

func dial(path string) net.Conn {
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %v\n", path, err)
		os.Exit(1)
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	return c
}

// call wraps ipc.Call so result is always a raw JSON value the test
// can interrogate generically — no app-specific struct dependency.
func call(conn net.Conn, method string, args map[string]any) map[string]any {
	var raw json.RawMessage
	if err := ipc.Call(conn, method, args, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", method, err)
		os.Exit(1)
	}
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			fmt.Fprintf(os.Stderr, "%s: bad json: %v\n", method, err)
			os.Exit(1)
		}
	}
	return out
}

func main() {
	payerSock := flag.String("payer", "", "payer wallet unix socket")
	merchantSock := flag.String("merchant", "", "merchant wallet unix socket")
	amount := flag.Uint64("amount", 50, "USDC amount to pay")
	flag.Parse()
	if *payerSock == "" || *merchantSock == "" {
		fmt.Fprintln(os.Stderr, "need -payer and -merchant")
		os.Exit(1)
	}

	payer := dial(*payerSock)
	defer payer.Close()
	merchant := dial(*merchantSock)
	defer merchant.Close()

	call(payer, "wallet.topup", map[string]any{
		"asset": "USDC", "amount": 100, "source": "smoke:faucet",
	})
	fmt.Println("topup OK")

	req := call(merchant, "wallet.request", map[string]any{
		"amount": *amount, "asset": "USDC",
		"expires_in_seconds": 60, "memo": "smoke",
	})
	challenge, ok := req["challenge"].(map[string]any)
	if !ok {
		body, _ := json.Marshal(req)
		fmt.Fprintf(os.Stderr, "no challenge in request resp: %s\n", body)
		os.Exit(1)
	}
	fmt.Println("challenge OK")

	pay := call(payer, "wallet.pay", map[string]any{"challenge": challenge})
	auth, ok := pay["signed_auth"].(map[string]any)
	if !ok {
		body, _ := json.Marshal(pay)
		fmt.Fprintf(os.Stderr, "no signed_auth in pay resp: %s\n", body)
		os.Exit(1)
	}
	fmt.Println("pay OK")

	ver := call(merchant, "wallet.verify", map[string]any{
		"challenge": challenge, "signed_auth": auth,
	})
	if ver["ok"] != true {
		fmt.Fprintln(os.Stderr, "verify ok != true on fresh auth")
		os.Exit(1)
	}

	settle := call(merchant, "wallet.settle", map[string]any{
		"challenge": challenge, "signed_auth": auth,
	})
	tx, _ := settle["transaction"].(map[string]any)
	if tx == nil {
		fmt.Fprintln(os.Stderr, "settle did not return a transaction")
		os.Exit(1)
	}
	// json.Unmarshal decodes numbers into float64 — the IPC
	// transparently round-trips uint, so a small whole number always
	// fits without precision loss.
	got, _ := tx["amount"].(float64)
	if uint64(got) != *amount {
		fmt.Fprintf(os.Stderr, "settle amount = %v, want %d\n", tx["amount"], *amount)
		os.Exit(1)
	}
	fmt.Println("settle OK")

	// Replay-guard: a second settle of the same SignedAuth must be
	// rejected. The wallet's anti-double-spend invariant; without it
	// a malicious merchant could claim the same payment twice.
	var ignore json.RawMessage
	replayErr := ipc.Call(merchant, "wallet.settle", map[string]any{
		"challenge": challenge, "signed_auth": auth,
	}, &ignore)
	if replayErr == nil {
		fmt.Fprintln(os.Stderr, "replay not rejected — anti-double-spend broken")
		os.Exit(1)
	}
	if !strings.Contains(replayErr.Error(), "already settled") {
		fmt.Fprintf(os.Stderr, "unexpected replay error: %v\n", replayErr)
		os.Exit(1)
	}
	fmt.Println("replay-guard OK")
	fmt.Println("PAY_OK")
}
