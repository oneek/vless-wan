package main

import (
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed core/*
var coreFiles embed.FS

const version = "0.4.1"

type listFlag []string

func (v *listFlag) String() string { return strings.Join(*v, ",") }
func (v *listFlag) Set(s string) error {
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			*v = append(*v, item)
		}
	}
	return nil
}

type options struct {
	all, insecure, dns            bool
	tun, logLevel                 string
	toNS                          string
	mtu                           int
	routes, domains               listFlag
	excludeRoutes, excludeDomains listFlag
}

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintln(os.Stderr, "vless-wan:", err)
		os.Exit(1)
	}
}

func realMain() error {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return errors.New("no command specified")
	}
	switch os.Args[1] {
	case "up", "check", "config":
		return handle(os.Args[1], os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("vless-wan %s (embedded Xray-core)\n", version)
		return nil
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		return handleShuttle(os.Args[1:])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `vless-wan — a VLESS VPN powered by embedded Xray-core

Usage (sshuttle style):
  vless-wan [options] -r 'vless://...' <networks or domains...>

Extended interface:
  vless-wan up [options] 'vless://...'
  vless-wan check [options] 'vless://...'
  vless-wan config [options] 'vless://...'

Routing:
  -r, --remote URL         VLESS share URL
  <routes...>              CIDRs, IPs, or domains; 0/0 means all IPv4
  -x, --exclude TARGET     route a network or domain directly (repeatable)
  --dns                    intercept DNS and send it through VLESS
  --to-ns IP[:PORT]        DNS upstream (default: 1.1.1.1:53)
  --all                    route all IPv4 and IPv6 traffic through VLESS
  --route CIDR             route a CIDR through VLESS (repeatable)
  --domain DOMAIN          route a domain and its subdomains (repeatable)

Options:
  --exclude-route CIDR     route a CIDR directly
  --exclude-domain DOMAIN  route a domain directly
  --tun NAME               TUN interface name (default: vless-wan0)
  --mtu N                  TUN MTU (default: 9000)
  --insecure               disable TLS certificate verification
  --log-level LEVEL        trace/debug/info/warn/error

The tunnel runs in the foreground until Ctrl+C. Root or CAP_NET_ADMIN is required.`)
}

func handleShuttle(args []string) error {
	var o options
	var remote string
	var excludes listFlag
	fs := flag.NewFlagSet("vless-wan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&remote, "r", "", "VLESS URL")
	fs.StringVar(&remote, "remote", "", "VLESS URL")
	fs.Var(&excludes, "x", "exclude subnet or hostname")
	fs.Var(&excludes, "exclude", "exclude subnet or hostname")
	fs.BoolVar(&o.dns, "dns", false, "proxy DNS through VLESS")
	fs.StringVar(&o.toNS, "to-ns", "1.1.1.1:53", "remote DNS server")
	fs.StringVar(&o.tun, "tun", "vless-wan0", "TUN interface name")
	fs.IntVar(&o.mtu, "mtu", 9000, "TUN MTU")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification")
	fs.StringVar(&o.logLevel, "log-level", "info", "log level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if remote == "" {
		return errors.New("specify a VLESS URL with -r/--remote")
	}
	if fs.NArg() == 0 {
		return errors.New("specify at least one route, for example 0/0 or 10.0.0.0/8")
	}
	for _, target := range fs.Args() {
		if err := addTarget(target, &o.routes, &o.domains); err != nil {
			return err
		}
	}
	for _, target := range excludes {
		if err := addTarget(target, &o.excludeRoutes, &o.excludeDomains); err != nil {
			return err
		}
	}
	outbound, err := parseVLESS(remote, o.insecure)
	if err != nil {
		return err
	}
	config, err := makeConfig(outbound, o)
	if err != nil {
		return err
	}
	return runCore(config, false, o)
}

func addTarget(target string, cidrs, domains *listFlag) error {
	target = strings.TrimSpace(target)
	if target == "0/0" {
		target = "0.0.0.0/0"
	}
	if ip := net.ParseIP(target); ip != nil {
		if ip.To4() != nil {
			target += "/32"
		} else {
			target += "/128"
		}
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		*cidrs = append(*cidrs, target)
		return nil
	}
	if strings.ContainsAny(target, "/ :") || target == "" {
		return fmt.Errorf("invalid network or domain %q", target)
	}
	*domains = append(*domains, target)
	return nil
}

func handle(command string, args []string) error {
	var o options
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&o.all, "all", false, "route all traffic through VLESS")
	fs.Var(&o.routes, "route", "CIDR routed through VLESS")
	fs.Var(&o.domains, "domain", "domain suffix routed through VLESS")
	fs.Var(&o.excludeRoutes, "exclude-route", "CIDR routed directly")
	fs.Var(&o.excludeDomains, "exclude-domain", "domain suffix routed directly")
	fs.StringVar(&o.tun, "tun", "vless-wan0", "TUN interface name")
	fs.IntVar(&o.mtu, "mtu", 9000, "TUN MTU")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&o.dns, "dns", false, "proxy DNS through VLESS")
	fs.StringVar(&o.toNS, "to-ns", "1.1.1.1:53", "remote DNS server")
	fs.StringVar(&o.logLevel, "log-level", "info", "log level")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("expected exactly one VLESS URL (options must precede the URL)")
	}
	if !o.all && len(o.routes) == 0 && len(o.domains) == 0 {
		return errors.New("select --all or add --route/--domain")
	}
	if o.all && (len(o.routes) > 0 || len(o.domains) > 0) {
		return errors.New("--all cannot be combined with --route/--domain")
	}
	outbound, err := parseVLESS(fs.Arg(0), o.insecure)
	if err != nil {
		return err
	}
	config, err := makeConfig(outbound, o)
	if err != nil {
		return err
	}
	if command == "config" {
		_, err = os.Stdout.Write(config)
		return err
	}
	return runCore(config, command == "check", o)
}

func parseVLESS(raw string, forceInsecure bool) (map[string]any, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" {
		return nil, errors.New("invalid vless:// URL")
	}
	if u.User == nil || u.User.Username() == "" || u.Hostname() == "" {
		return nil, errors.New("VLESS URL must contain a UUID and server address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("VLESS URL must contain a valid port")
	}
	q := u.Query()
	user := map[string]any{
		"id":         u.User.Username(),
		"encryption": q.Get("encryption"),
	}
	if user["encryption"] == "" {
		user["encryption"] = "none"
	}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	out := map[string]any{
		"protocol": "vless", "tag": "vless-out",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": u.Hostname(), "port": port, "users": []any{user},
		}}},
	}
	stream := map[string]any{"network": "tcp"}
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		stream["security"] = security
		tls := map[string]any{}
		if sni := first(q, "sni", "serverName"); sni != "" {
			tls["serverName"] = sni
		} else {
			tls["serverName"] = u.Hostname()
		}
		if forceInsecure || truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) {
			tls["allowInsecure"] = true
		}
		if alpn := splitCSV(q.Get("alpn")); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		if fp := q.Get("fp"); fp != "" && fp != "none" {
			tls["fingerprint"] = fp
		}
		if security == "reality" {
			pbk := first(q, "pbk", "publicKey")
			if pbk == "" {
				return nil, errors.New("REALITY URL does not contain pbk/publicKey")
			}
			tls["publicKey"] = pbk
			tls["shortId"] = first(q, "sid", "shortId")
			stream["realitySettings"] = tls
		} else {
			stream["tlsSettings"] = tls
		}
	} else if security != "" && security != "none" {
		return nil, fmt.Errorf("unsupported security=%q", security)
	}
	switch typ := q.Get("type"); typ {
	case "", "tcp", "raw":
		stream["network"] = "tcp"
		if headerType := q.Get("headerType"); headerType != "" && headerType != "none" {
			header := map[string]any{"type": headerType}
			if p := q.Get("path"); p != "" {
				header["request"] = map[string]any{"path": []string{p}}
			}
			stream["tcpSettings"] = map[string]any{"header": header}
		}
	case "ws":
		stream["network"] = "ws"
		t := map[string]any{}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if host := q.Get("host"); host != "" {
			t["host"] = host
		}
		stream["wsSettings"] = t
	case "grpc":
		stream["network"] = "grpc"
		t := map[string]any{}
		if name := first(q, "serviceName", "service_name"); name != "" {
			t["serviceName"] = name
		}
		stream["grpcSettings"] = t
	case "httpupgrade":
		stream["network"] = "httpupgrade"
		t := map[string]any{}
		if p := q.Get("path"); p != "" {
			t["path"] = p
		}
		if host := q.Get("host"); host != "" {
			t["host"] = host
		}
		stream["httpupgradeSettings"] = t
	default:
		return nil, fmt.Errorf("unsupported transport type=%q", typ)
	}
	out["streamSettings"] = stream
	return out, nil
}

func makeConfig(vless map[string]any, o options) ([]byte, error) {
	for _, cidr := range append(append([]string{}, o.routes...), o.excludeRoutes...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", cidr)
		}
	}
	cleanDomains := func(in []string) ([]string, error) {
		out := make([]string, 0, len(in))
		for _, d := range in {
			d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" || strings.ContainsAny(d, "/ :") {
				return nil, fmt.Errorf("invalid domain %q", d)
			}
			out = append(out, d)
		}
		return out, nil
	}
	domains, err := cleanDomains(o.domains)
	if err != nil {
		return nil, err
	}
	exDomains, err := cleanDomains(o.excludeDomains)
	if err != nil {
		return nil, err
	}

	rules := []any{}
	if len(o.excludeRoutes) > 0 || len(exDomains) > 0 {
		r := map[string]any{"type": "field", "outboundTag": "direct"}
		if len(o.excludeRoutes) > 0 {
			r["ip"] = []string(o.excludeRoutes)
		}
		if len(exDomains) > 0 {
			r["domain"] = prefixDomains(exDomains)
		}
		rules = append(rules, r)
	}
	if !o.all {
		r := map[string]any{"type": "field", "outboundTag": "vless-out"}
		if len(o.routes) > 0 {
			r["ip"] = []string(o.routes)
		}
		if len(domains) > 0 {
			r["domain"] = prefixDomains(domains)
		}
		rules = append(rules, r)
		rules = append(rules, map[string]any{
			"type": "field", "network": "tcp,udp", "outboundTag": "direct",
		})
	}
	outbounds := []any{vless, map[string]any{
		"protocol": "freedom", "tag": "direct", "settings": map[string]any{},
	}}
	dnsConfig := map[string]any{"servers": []any{"localhost"}}
	if o.dns {
		host, port, err := parseNameServer(o.toNS)
		if err != nil {
			return nil, err
		}
		dnsConfig["servers"] = []any{map[string]any{
			"address": host,
			"port":    port,
		}}
		outbounds = append(outbounds, map[string]any{
			"protocol": "dns", "tag": "dns-out",
			"settings":      map[string]any{"address": host, "port": port, "network": "tcp,udp"},
			"proxySettings": map[string]any{"tag": "vless-out"},
		})
		rules = append([]any{map[string]any{
			"type": "field", "network": "udp", "port": "53", "outboundTag": "dns-out",
		}}, rules...)
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": xrayLogLevel(o.logLevel)},
		"dns": dnsConfig,
		"inbounds": []any{map[string]any{
			"protocol": "tun", "tag": "tun-in",
			"settings": map[string]any{
				"name": o.tun, "mtu": o.mtu,
				"gateway":                []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"autoSystemRoutingTable": []string{"0.0.0.0/0", "::/0"},
				"autoOutboundsInterface": "auto",
			},
			"sniffing": map[string]any{
				"enabled": true, "destOverride": []string{"http", "tls", "quic"},
				"routeOnly": true,
			},
		}},
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	return append(data, '\n'), err
}

func prefixDomains(domains []string) []string {
	out := make([]string, len(domains))
	for i, domain := range domains {
		out[i] = "domain:" + domain
	}
	return out
}

func xrayLogLevel(level string) string {
	if level == "trace" {
		return "debug"
	}
	if level == "warn" {
		return "warning"
	}
	return level
}

func parseNameServer(value string) (string, int, error) {
	if ip := net.ParseIP(value); ip != nil {
		return value, 53, nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("--to-ns: expected IP or IP:PORT, got %q", value)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("--to-ns: %q is not an IP address", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("--to-ns: invalid port %q", portText)
	}
	return host, port, nil
}

func runCore(config []byte, check bool, o options) error {
	dir, err := os.MkdirTemp("", "vless-wan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	corePath := filepath.Join(dir, "xray")
	xrayCore, err := coreFiles.ReadFile("core/xray")
	if err != nil || len(xrayCore) < 1024*1024 {
		return errors.New("Xray-core is not embedded; build a release with make build")
	}
	if err := os.WriteFile(corePath, xrayCore, 0700); err != nil {
		return err
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		return err
	}
	args := []string{"run", "-c", configPath}
	if check {
		args = []string{"run", "-test", "-c", configPath}
	}
	cmd := exec.Command(corePath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if check {
		return cmd.Run()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := installRoutes(o); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		return err
	}
	defer removeRoutes(o)
	go func() {
		sig := <-signals
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
	}()
	err = cmd.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 0 {
		return nil
	}
	return err
}

func kernelRoutes(o options) []string {
	if o.all || len(o.domains) > 0 {
		return []string{"0.0.0.0/0", "::/0"}
	}
	return append([]string(nil), o.routes...)
}

func systemRoutes(o options) []string {
	var routes []string
	for _, route := range kernelRoutes(o) {
		switch route {
		case "0.0.0.0/0":
			routes = append(routes, "0.0.0.0/1", "128.0.0.0/1")
		case "::/0":
			routes = append(routes, "::/1", "8000::/1")
		default:
			routes = append(routes, route)
		}
	}
	return routes
}

func installRoutes(o options) error {
	var lastErr error
	for i := 0; i < 50; i++ {
		if _, err := net.InterfaceByName(o.tun); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("TUN interface %s did not appear: %w", o.tun, lastErr)
	}
	for _, route := range systemRoutes(o) {
		family := "-4"
		if strings.Contains(route, ":") {
			family = "-6"
		}
		if output, err := exec.Command("ip", family, "route", "replace", route,
			"dev", o.tun, "metric", "1").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install route %s: %v: %s",
				route, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func removeRoutes(o options) {
	for _, route := range systemRoutes(o) {
		family := "-4"
		if strings.Contains(route, ":") {
			family = "-6"
		}
		_ = exec.Command("ip", family, "route", "del", route,
			"dev", o.tun, "metric", "1").Run()
	}
}

func first(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}
func truthy(s string) bool { b, _ := strconv.ParseBool(s); return b }
func splitCSV(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
