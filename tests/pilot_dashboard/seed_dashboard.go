package pilot_dashboard

import (
	"encoding/base64"
	"log"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// SeedRegistry populates a registry with test nodes, tags, and trust relationships
// for dashboard testing purposes.
func SeedRegistry(registryAddr string) error {
	log.Printf("Connecting to registry at %s...", registryAddr)

	rc, err := registry.Dial(registryAddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Seed test nodes with various configurations
	nodes := []struct {
		addr      string
		hostname  string
		tags      []string
		taskExec  bool
		poloScore int
	}{
		{"192.168.1.10:8000", "ml-gpu-1", []string{"ml", "gpu", "training"}, true, 150},
		{"192.168.1.11:8000", "ml-gpu-2", []string{"ml", "gpu", "inference"}, true, 125},
		{"192.168.1.12:8000", "storage-1", []string{"storage", "backup"}, false, 45},
		{"192.168.1.13:8000", "compute-1", []string{"compute", "batch"}, true, 92},
		{"192.168.1.14:8000", "webserver-1", []string{"webserver", "api"}, true, 110},
		{"192.168.1.15:8000", "webserver-2", []string{"webserver", "frontend"}, false, 68},
		{"192.168.1.16:8000", "database-1", []string{"database", "postgres"}, false, 78},
		{"192.168.1.17:8000", "cache-1", []string{"cache", "redis"}, false, 55},
		{"192.168.1.18:8000", "assistant-1", []string{"assistant", "nlp"}, true, 135},
		{"192.168.1.19:8000", "monitor-1", []string{"monitoring", "metrics"}, false, 30},
	}

	registeredNodes := make([]struct {
		id       uint32
		identity *crypto.Identity
		addr     string
	}, 0, len(nodes))

	log.Println("Registering nodes...")
	for i, n := range nodes {
		// Generate identity for this node
		id, err := crypto.GenerateIdentity()
		if err != nil {
			log.Printf("failed to generate identity for node %d: %v", i, err)
			continue
		}

		// Register node
		msg := map[string]interface{}{
			"type":        "register",
			"listen_addr": n.addr,
			"public_key":  crypto.EncodePublicKey(id.PublicKey),
		}
		if n.hostname != "" {
			msg["hostname"] = n.hostname
		}
		if n.taskExec {
			msg["task_exec"] = true
		}

		resp, err := rc.Send(msg)
		if err != nil {
			log.Printf("failed to register %s: %v", n.addr, err)
			continue
		}

		if resp["type"] != "register_ok" {
			log.Printf("unexpected response for %s: %v", n.addr, resp)
			continue
		}

		nodeID := uint32(resp["node_id"].(float64))
		log.Printf("✓ Registered %s (ID: %d, hostname: %s)", n.addr, nodeID, n.hostname)

		// Store for later operations
		registeredNodes = append(registeredNodes, struct {
			id       uint32
			identity *crypto.Identity
			addr     string
		}{nodeID, id, n.addr})

		// Set tags if any
		if len(n.tags) > 0 {
			// Create a new client with signer for authenticated operations
			rcAuth, err := registry.Dial(registryAddr)
			if err != nil {
				log.Printf("failed to create auth client for %s: %v", n.addr, err)
				continue
			}

			// Set signer
			rcAuth.SetSigner(func(challenge string) string {
				sig := id.Sign([]byte(challenge))
				return base64.StdEncoding.EncodeToString(sig)
			})

			setTagsMsg := map[string]interface{}{
				"type":    "set_tags",
				"node_id": nodeID,
				"tags":    n.tags,
			}

			tagResp, err := rcAuth.Send(setTagsMsg)
			if err != nil {
				log.Printf("  ⚠ failed to set tags for %s: %v", n.addr, err)
			} else if tagResp["type"] == "set_tags_ok" {
				log.Printf("  ✓ Set tags: %v", n.tags)
			}

			rcAuth.Close()
		}

		// Set POLO score if specified
		if n.poloScore > 0 {
			rcScore, err := registry.Dial(registryAddr)
			if err != nil {
				log.Printf("  ⚠ failed to create client for polo score: %v", err)
				continue
			}

			rcScore.SetSigner(func(challenge string) string {
				sig := id.Sign([]byte(challenge))
				return base64.StdEncoding.EncodeToString(sig)
			})

			setScoreMsg := map[string]interface{}{
				"type":       "set_polo_score",
				"node_id":    nodeID,
				"polo_score": n.poloScore,
			}

			scoreResp, err := rcScore.Send(setScoreMsg)
			if err != nil {
				log.Printf("  ⚠ failed to set POLO score for %s: %v", n.addr, err)
			} else if scoreResp["type"] == "set_polo_score_ok" {
				log.Printf("  ✓ Set POLO score: %d", n.poloScore)
			}

			rcScore.Close()
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Establish some trust relationships
	log.Println("\nEstablishing trust relationships...")
	trustPairs := [][2]int{
		{0, 1}, // ml-gpu-1 <-> ml-gpu-2
		{4, 5}, // webserver-1 <-> webserver-2
		{0, 8}, // ml-gpu-1 <-> assistant-1
		{2, 3}, // storage-1 <-> compute-1
		{6, 7}, // database-1 <-> cache-1
	}

	for _, pair := range trustPairs {
		if pair[0] >= len(registeredNodes) || pair[1] >= len(registeredNodes) {
			continue
		}

		nodeA := registeredNodes[pair[0]]
		nodeB := registeredNodes[pair[1]]

		// Create authenticated clients for both nodes
		rcA, err := registry.Dial(registryAddr)
		if err != nil {
			continue
		}
		rcA.SetSigner(func(challenge string) string {
			sig := nodeA.identity.Sign([]byte(challenge))
			return base64.StdEncoding.EncodeToString(sig)
		})

		rcB, err := registry.Dial(registryAddr)
		if err != nil {
			rcA.Close()
			continue
		}
		rcB.SetSigner(func(challenge string) string {
			sig := nodeB.identity.Sign([]byte(challenge))
			return base64.StdEncoding.EncodeToString(sig)
		})

		// Add trust A -> B
		addTrustMsg := map[string]interface{}{
			"type":    "add_trust",
			"node_id": nodeA.id,
			"peer_id": nodeB.id,
		}
		_, err = rcA.Send(addTrustMsg)
		if err != nil {
			log.Printf("  ⚠ failed to add trust %d -> %d: %v", nodeA.id, nodeB.id, err)
		} else {
			log.Printf("  ✓ Trust: %s -> %s", nodeA.addr, nodeB.addr)
		}

		// Add trust B -> A
		addTrustMsg = map[string]interface{}{
			"type":    "add_trust",
			"node_id": nodeB.id,
			"peer_id": nodeA.id,
		}
		_, err = rcB.Send(addTrustMsg)
		if err != nil {
			log.Printf("  ⚠ failed to add trust %d -> %d: %v", nodeB.id, nodeA.id, err)
		} else {
			log.Printf("  ✓ Trust: %s -> %s", nodeB.addr, nodeA.addr)
		}

		rcA.Close()
		rcB.Close()

		time.Sleep(100 * time.Millisecond)
	}

	log.Println("\n✅ Seeding complete!")
	log.Printf("Dashboard should show %d nodes with tags and %d trust relationships", len(registeredNodes), len(trustPairs)*2)

	return nil
}
