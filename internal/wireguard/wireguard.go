package wireguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"wgvpn/internal/config"
)

type UserInfo struct {
	Login        string `json:"login"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	AllowedIPs   string `json:"allowed_ips"`
}

type usersDB struct {
	Users map[string]*UserInfo `json:"users"`
	path  string
}

func loadUsersDB(path string) (*usersDB, error) {
	db := &usersDB{
		Users: make(map[string]*UserInfo),
		path:  path,
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}

	return db, json.Unmarshal(data, &db.Users)
}

func (db *usersDB) save() error {
	if err := os.MkdirAll(parentDir(db.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(db.Users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0600)
}

// WireGuard manages the wg config file, user database, and service lifecycle.
type WireGuard struct {
	cfg   *config.Config
	users *usersDB
}

func New(cfg *config.Config) (*WireGuard, error) {
	db, err := loadUsersDB(cfg.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("load users db: %w", err)
	}
	w := &WireGuard{cfg: cfg, users: db}
	if err := w.rewriteConfig(); err != nil {
		return nil, fmt.Errorf("initial config sync: %w", err)
	}
	if err := w.syncConf(); err != nil {
		return nil, fmt.Errorf("initial wg sync: %w", err)
	}
	return w, nil
}

// AddUser generates keys, assigns the next free IP, updates wg.conf, and syncs.
func (w *WireGuard) AddUser(login string) (*UserInfo, error) {
	if _, exists := w.users.Users[login]; exists {
		return nil, fmt.Errorf("user %q already exists", login)
	}

	priv, pub, psk, err := w.generateKeys()
	if err != nil {
		return nil, err
	}

	ip, err := w.nextIP()
	if err != nil {
		return nil, err
	}

	user := &UserInfo{
		Login:        login,
		PrivateKey:   priv,
		PublicKey:    pub,
		PresharedKey: psk,
		AllowedIPs:   ip,
	}
	w.users.Users[login] = user

	if err := w.users.save(); err != nil {
		return nil, fmt.Errorf("save users db: %w", err)
	}
	if err := w.rewriteConfig(); err != nil {
		return nil, fmt.Errorf("rewrite wg config: %w", err)
	}
	if err := w.syncConf(); err != nil {
		return nil, fmt.Errorf("sync wg config: %w", err)
	}

	return user, nil
}

// DelUser removes the peer and syncs.
func (w *WireGuard) DelUser(login string) error {
	if _, exists := w.users.Users[login]; !exists {
		return fmt.Errorf("user %q not found", login)
	}

	delete(w.users.Users, login)

	if err := w.users.save(); err != nil {
		return fmt.Errorf("save users db: %w", err)
	}
	if err := w.rewriteConfig(); err != nil {
		return fmt.Errorf("rewrite wg config: %w", err)
	}
	if err := w.syncConf(); err != nil {
		return fmt.Errorf("sync wg config: %w", err)
	}

	return nil
}

func (w *WireGuard) ListUsers() []*UserInfo {
	list := make([]*UserInfo, 0, len(w.users.Users))
	for _, u := range w.users.Users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Login < list[j].Login })
	return list
}

func (w *WireGuard) GetUser(login string) (*UserInfo, bool) {
	u, ok := w.users.Users[login]
	return u, ok
}

// PeerStats holds live traffic counters for one peer from `wg show dump`.
type PeerStats struct {
	LastHandshake time.Time // zero if peer has never connected
	RxBytes       int64
	TxBytes       int64
}

// PeerStatsMap returns a map[publicKey]*PeerStats from the running interface.
// Returns nil (no error) if the interface is not up.
func (w *WireGuard) PeerStatsMap() map[string]*PeerStats {
	out, err := exec.Command("wg", "show", w.cfg.WGInterface, "dump").Output()
	if err != nil {
		return nil
	}

	result := make(map[string]*PeerStats)
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 || line == "" {
			continue // first line is the interface itself
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		ts, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)

		s := &PeerStats{RxBytes: rx, TxBytes: tx}
		if ts > 0 {
			s.LastHandshake = time.Unix(ts, 0)
		}
		result[f[0]] = s // f[0] is the peer public key
	}
	return result
}

// ClientConfig returns the content of the client .conf file.
func (w *WireGuard) ClientConfig(u *UserInfo) string {
	return fmt.Sprintf(
		"[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n"+
			"[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		u.PrivateKey, u.AllowedIPs, w.cfg.DNS,
		w.cfg.ServerPublicKey, u.PresharedKey,
		w.cfg.ServerEndpoint, w.cfg.ClientAllowedIPs,
	)
}

func (w *WireGuard) IsActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "wg-quick@"+w.cfg.WGInterface).Run() == nil
}

func (w *WireGuard) StartService() error {
	out, err := exec.Command("systemctl", "start", "wg-quick@"+w.cfg.WGInterface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (w *WireGuard) StopService() error {
	out, err := exec.Command("systemctl", "stop", "wg-quick@"+w.cfg.WGInterface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (w *WireGuard) Status() (string, error) {
	out, err := exec.Command("wg", "show").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wg show: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// rewriteConfig preserves [Interface] from disk and rebuilds all [Peer] blocks.
func (w *WireGuard) rewriteConfig() error {
	existing, err := os.ReadFile(w.cfg.WGConfigPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", w.cfg.WGConfigPath, err)
	}

	var sb strings.Builder
	sb.WriteString(extractInterfaceSection(string(existing)))
	sb.WriteString("\n")

	for _, u := range w.ListUsers() {
		fmt.Fprintf(&sb, "\n# BEGIN_PEER %s\n", u.Login)
		sb.WriteString("[Peer]\n")
		fmt.Fprintf(&sb, "# Name = %s\n", u.Login)
		fmt.Fprintf(&sb, "PublicKey = %s\n", u.PublicKey)
		fmt.Fprintf(&sb, "PresharedKey = %s\n", u.PresharedKey)
		fmt.Fprintf(&sb, "AllowedIPs = %s\n", u.AllowedIPs)
		fmt.Fprintf(&sb, "# END_PEER %s\n", u.Login)
	}

	return os.WriteFile(w.cfg.WGConfigPath, []byte(sb.String()), 0600)
}

// syncConf hot-applies the config to a running interface via wg syncconf.
func (w *WireGuard) syncConf() error {
	if err := exec.Command("systemctl", "is-active", "--quiet", "wg-quick@"+w.cfg.WGInterface).Run(); err != nil {
		return nil // service not running
	}

	content, err := os.ReadFile(w.cfg.WGConfigPath)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "wg-syncconf-*.conf")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(stripWGQuickDirectives(string(content))); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	out, err := exec.Command("wg", "syncconf", w.cfg.WGInterface, tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (w *WireGuard) generateKeys() (priv, pub, psk string, err error) {
	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", "", fmt.Errorf("wg genkey: %w", err)
	}
	priv = strings.TrimSpace(string(out))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv)
	out, err = cmd.Output()
	if err != nil {
		return "", "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	pub = strings.TrimSpace(string(out))

	out, err = exec.Command("wg", "genpsk").Output()
	if err != nil {
		return "", "", "", fmt.Errorf("wg genpsk: %w", err)
	}
	psk = strings.TrimSpace(string(out))

	return priv, pub, psk, nil
}

func (w *WireGuard) nextIP() (string, error) {
	_, ipNet, err := net.ParseCIDR(w.cfg.Subnet)
	if err != nil {
		return "", fmt.Errorf("parse subnet %q: %w", w.cfg.Subnet, err)
	}

	used := map[string]bool{w.cfg.ServerIP: true}
	for _, u := range w.users.Users {
		if ip, _, _ := net.ParseCIDR(u.AllowedIPs); ip != nil {
			used[ip.String()] = true
		}
	}

	bcast := broadcastIP(ipNet)
	ip := cloneIP(ipNet.IP.To4())
	incIP(ip) // skip network address

	for ipNet.Contains(ip) {
		if s := ip.String(); !used[s] && s != bcast {
			return s + "/32", nil
		}
		incIP(ip)
	}

	return "", fmt.Errorf("no available IPs in subnet %s", w.cfg.Subnet)
}

func broadcastIP(n *net.IPNet) string {
	ip := n.IP.To4()
	if ip == nil {
		return ""
	}
	b := make(net.IP, 4)
	for i := range ip {
		b[i] = ip[i] | ^n.Mask[i]
	}
	return b.String()
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// extractInterfaceSection returns the [Interface] block without trailing blank lines.
func extractInterfaceSection(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inside := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Interface]" {
			inside = true
		} else if inside && strings.HasPrefix(trimmed, "[") {
			break
		}
		if inside {
			result = append(result, line)
		}
	}

	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}
	return strings.Join(result, "\n")
}

// stripWGQuickDirectives removes keys that wg-quick adds but wg syncconf does not understand.
func stripWGQuickDirectives(content string) string {
	skip := map[string]bool{
		"Address": true, "DNS": true, "MTU": true, "Table": true,
		"PreUp": true, "PostUp": true, "PreDown": true, "PostDown": true,
		"SaveConfig": true,
	}
	lines := strings.Split(content, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if !skip[key] {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

func parentDir(path string) string {
	i := strings.LastIndexAny(path, "/\\")
	if i < 0 {
		return "."
	}
	return path[:i]
}
