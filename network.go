package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const bypassMark = 0x56000000
const ruleBase = 10000

type ipRunner func(...string) ([]byte, error)

func runIP(args ...string) ([]byte, error) {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

type addressInfo struct {
	Family    string   `json:"family"`
	Local     string   `json:"local"`
	PrefixLen int      `json:"prefixlen"`
	Flags     []string `json:"flags"`
}
type interfaceInfo struct {
	Name      string        `json:"ifname"`
	Flags     []string      `json:"flags"`
	Addresses []addressInfo `json:"addr_info"`
}
type routeInfo struct {
	Dst     string `json:"dst"`
	Dev     string `json:"dev"`
	Scope   string `json:"scope"`
	Type    string `json:"type"`
	Gateway string `json:"gateway"`
	Table   any    `json:"table"`
}
type familyState struct {
	flag      string
	addresses []string
	connected []string
}
type networkSession struct {
	o        options
	run      ipRunner
	lock     net.Listener
	table    string
	families []familyState
	undo     [][]string
}

// An abstract Unix socket is scoped to the network namespace and released even
// on SIGKILL. No stale lock file or host-network mutation is needed.
func prepareNetwork(o options, run ipRunner) (*networkSession, error) {
	lock, err := net.Listen("unix", "\x00vless-wan-policy-routing-v1")
	if err != nil {
		return nil, fmt.Errorf("another vless-wan instance is running in this network namespace: %w", err)
	}
	s := &networkSession{o: o, run: run, lock: lock}
	if err := s.inspect(); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *networkSession) readJSON(dst any, args ...string) error {
	data, err := s.run(args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode ip %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (s *networkSession) inspect() error {
	var interfaces []interfaceInfo
	if err := s.readJSON(&interfaces, "-j", "address", "show"); err != nil {
		return err
	}
	usedTables := map[string]bool{}
	for _, flag := range []string{"-4", "-6"} {
		var rules []map[string]any
		if err := s.readJSON(&rules, "-j", flag, "rule", "show"); err != nil {
			return err
		}
		local, main := false, false
		for _, r := range rules {
			pref, ok := r["priority"].(float64)
			table, _ := r["table"].(string)
			standard := ok && (pref == 0 && table == "local" || pref == 32766 && table == "main" || pref == 32767 && table == "default")
			for key := range r {
				if key != "priority" && key != "src" && key != "table" && key != "protocol" {
					standard = false
				}
			}
			if src, ok := r["src"]; ok && src != "all" {
				standard = false
			}
			if !standard {
				return fmt.Errorf("unsupported existing %s policy routing; stop other VPNs and remove stale vless-wan rules before starting", flag)
			}
			local = local || pref == 0
			main = main || pref == 32766
		}
		if !local || !main {
			return fmt.Errorf("%s requires the standard local and main policy rules", flag)
		}
		var routes []routeInfo
		if err := s.readJSON(&routes, "-N", "-j", flag, "route", "show", "table", "all"); err != nil {
			return err
		}
		f := familyState{flag: flag}
		for _, r := range routes {
			if r.Table != nil {
				usedTables[fmt.Sprint(r.Table)] = true
			}
			if r.Table != nil && fmt.Sprint(r.Table) != "main" && fmt.Sprint(r.Table) != "254" {
				continue
			}
			if r.Scope == "link" && r.Gateway == "" && r.Dst != "" && r.Dst != "default" && r.Dev != "lo" && (r.Type == "" || r.Type == "unicast") {
				f.connected = appendUnique(f.connected, r.Dst)
			}
			// IPv6 connected routes do not carry scope=link in iproute2 JSON.
			if flag == "-6" && r.Gateway == "" && r.Dev != "lo" && r.Dev != "" && r.Dst != "default" && r.Dst != "" && (r.Type == "" || r.Type == "unicast") {
				f.connected = appendUnique(f.connected, r.Dst)
			}
		}
		for _, iface := range interfaces {
			if iface.Name == s.o.tun || contains(iface.Flags, "LOOPBACK") {
				continue
			}
			for _, a := range iface.Addresses {
				if (flag == "-4") != (a.Family == "inet") {
					continue
				}
				if a.Family != "inet" && a.Family != "inet6" {
					continue
				}
				ip := net.ParseIP(a.Local)
				if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
					continue
				}
				bits := 128
				if flag == "-4" {
					bits = 32
				}
				f.addresses = appendUnique(f.addresses, fmt.Sprintf("%s/%d", ip, bits))
			}
		}
		s.families = append(s.families, f)
	}
	for table := 20000; table < 20100; table++ {
		if !usedTables[strconv.Itoa(table)] {
			s.table = strconv.Itoa(table)
			break
		}
	}
	if s.table == "" {
		return errors.New("no free VPN routing table in range 20000..20099")
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func appendUnique(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func (s *networkSession) add(args ...string) error {
	if _, err := s.run(args...); err != nil {
		return err
	}
	inverse := append([]string(nil), args...)
	inverse[2] = "del" // family, route/rule, add
	s.undo = append(s.undo, inverse)
	return nil
}

func (s *networkSession) tunSources() (map[string]string, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		var interfaces []interfaceInfo
		if err := s.readJSON(&interfaces, "-j", "address", "show", "dev", s.o.tun); err != nil {
			return nil, err
		}
		sources := map[string]string{}
		for _, iface := range interfaces {
			for _, a := range iface.Addresses {
				if contains(a.Flags, "tentative") || contains(a.Flags, "dadfailed") {
					continue
				}
				if a.Local == "172.19.0.1" {
					sources["-4"] = a.Local
				}
				if a.Local == "fdfe:dcba:9876::1" {
					sources["-6"] = a.Local
				}
			}
		}
		ready := true
		for _, route := range kernelRoutes(s.o) {
			flag := "-4"
			if strings.Contains(route, ":") {
				flag = "-6"
			}
			if sources[flag] == "" {
				ready = false
			}
		}
		if ready {
			return sources, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("TUN addresses are missing or not ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *networkSession) activate() error {
	sources, err := s.tunSources()
	if err != nil {
		return err
	}
	// Only the newly created interface is changed; deleting it removes this setting.
	if strings.ContainsAny(s.o.tun, "/\x00") {
		return errors.New("invalid TUN interface name")
	}
	path := "/proc/sys/net/ipv4/conf/" + s.o.tun + "/rp_filter"
	if err := os.WriteFile(path, []byte("2\n"), 0600); err != nil {
		return fmt.Errorf("set TUN reverse-path filtering: %w", err)
	}
	// Build both tables before enabling either family's catch-all rule.
	for _, f := range s.families {
		for _, cidr := range kernelRoutes(s.o) {
			if strings.Contains(cidr, ":") != (f.flag == "-6") || contains(f.connected, cidr) {
				continue
			}
			if err := s.add(f.flag, "route", "add", "table", s.table, cidr, "dev", s.o.tun, "src", sources[f.flag]); err != nil {
				return err
			}
		}
		for _, cidr := range f.connected {
			if err := s.add(f.flag, "route", "add", "table", s.table, "throw", cidr); err != nil {
				return err
			}
		}
		pref := ruleBase
		rule := func(selectors ...string) error {
			args := []string{f.flag, "rule", "add", "pref", strconv.Itoa(pref)}
			pref++
			if pref >= 32765 {
				return errors.New("too many bypass policy rules")
			}
			return s.add(append(args, selectors...)...)
		}
		if err := rule("fwmark", fmt.Sprintf("0x%x/0xffffffff", bypassMark), "lookup", "main"); err != nil {
			return err
		}
		for _, address := range f.addresses {
			if err := rule("from", address, "lookup", "main"); err != nil {
				return err
			}
		}
		for _, cidr := range s.o.excludeRoutes {
			if strings.Contains(cidr, ":") == (f.flag == "-6") {
				if err := rule("to", cidr, "lookup", "main"); err != nil {
					return err
				}
			}
		}
		fmt.Fprintf(os.Stderr, "vless-wan: %s policy table %s, bypass priorities %d..%d, VPN priority 32765\n", f.flag, s.table, ruleBase, pref-1)

	}
	for _, f := range s.families {
		// iif lo restricts this rule to locally originated traffic, not forwarding.
		if err := s.add(f.flag, "rule", "add", "pref", "32765", "iif", "lo", "lookup", s.table); err != nil {
			return err
		}
	}
	return nil
}

func (s *networkSession) cleanup() {
	var failed [][]string
	for i := len(s.undo) - 1; i >= 0; i-- {
		if _, err := s.run(s.undo[i]...); err != nil {
			// Routes attached to TUN vanish automatically if Xray exits first.
			if s.undo[i][1] == "route" && (strings.Contains(err.Error(), "No such process") || strings.Contains(err.Error(), "Cannot find device") || strings.Contains(err.Error(), "FIB table does not exist")) {
				continue
			}
			fmt.Fprintln(os.Stderr, "vless-wan: cleanup:", err)
			failed = append([][]string{s.undo[i]}, failed...)
		}
	}
	s.undo = failed
}
func (s *networkSession) close() {
	s.cleanup()
	if s.lock != nil {
		_ = s.lock.Close()
	}
}

// Ensure socket marking is supported before any routes are installed.
func checkSocketMark() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, bypassMark); err != nil {
		return fmt.Errorf("SO_MARK is required: %w", err)
	}
	return nil
}
