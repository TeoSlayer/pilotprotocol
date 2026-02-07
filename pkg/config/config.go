package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Load reads a JSON config file and returns it as a map.
func Load(path string) (map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg map[string]interface{}
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyToFlags overrides flag defaults from config for any flag not
// explicitly set on the command line. Call this AFTER flag.Parse().
// Keys in the config can use either hyphens or underscores (e.g.
// "log-level" or "log_level" both match the -log-level flag).
func ApplyToFlags(cfg map[string]interface{}) {
	explicit := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicit[f.Name] = true
	})

	flag.VisitAll(func(f *flag.Flag) {
		if explicit[f.Name] {
			return
		}
		val, ok := cfg[f.Name]
		if !ok {
			// Try underscore variant: log-level → log_level
			val, ok = cfg[strings.ReplaceAll(f.Name, "-", "_")]
		}
		if !ok {
			return
		}
		switch v := val.(type) {
		case string:
			f.Value.Set(v)
		case float64:
			f.Value.Set(fmt.Sprintf("%v", v))
		case bool:
			f.Value.Set(fmt.Sprintf("%v", v))
		}
	})
}
