package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	TelegramToken    string  `json:"telegram_token"`
	AdminIDs         []int64 `json:"admin_ids"`
	WGConfigPath     string  `json:"wg_config_path"`
	WGInterface      string  `json:"wg_interface"`
	ServerEndpoint   string  `json:"server_endpoint"`
	ServerPublicKey  string  `json:"server_public_key"`
	Subnet           string  `json:"subnet"`
	ServerIP         string  `json:"server_ip"`
	DNS              string  `json:"dns"`
	ClientAllowedIPs string  `json:"client_allowed_ips"`
	UsersFile        string  `json:"users_file"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if cfg.TelegramToken == "" {
		return nil, fmt.Errorf("telegram_token is required")
	}
	if len(cfg.AdminIDs) == 0 {
		return nil, fmt.Errorf("admin_ids must have at least one entry")
	}
	if cfg.ServerEndpoint == "" {
		return nil, fmt.Errorf("server_endpoint is required")
	}
	if cfg.ServerPublicKey == "" {
		return nil, fmt.Errorf("server_public_key is required")
	}

	if cfg.WGConfigPath == "" {
		cfg.WGConfigPath = "/etc/wireguard/wg0.conf"
	}
	if cfg.WGInterface == "" {
		cfg.WGInterface = "wg0"
	}
	if cfg.Subnet == "" {
		cfg.Subnet = "10.8.0.0/24"
	}
	if cfg.ServerIP == "" {
		cfg.ServerIP = "10.8.0.1"
	}
	if cfg.DNS == "" {
		cfg.DNS = "8.8.8.8"
	}
	if cfg.ClientAllowedIPs == "" {
		cfg.ClientAllowedIPs = "0.0.0.0/0, ::/0"
	}
	if cfg.UsersFile == "" {
		cfg.UsersFile = "/etc/wgvpn/users.json"
	}

	return &cfg, nil
}
