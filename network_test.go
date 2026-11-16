package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNetworkInspection(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint(custom), func(t *testing.T) {
			s := &networkSession{o: options{tun: "vpn0"}, run: func(args ...string) ([]byte, error) {
				command := strings.Join(args, " ")
				switch {
				case strings.Contains(command, "rule show"):
					rules := `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`
					if custom {
						rules = `[{"priority":100,"src":"all","table":"other"}]`
					}
					return []byte(rules), nil
				case strings.Contains(command, "route show"):
					return []byte(`[{"dst":"192.0.2.0/24","dev":"eth0","scope":"link"},{"dst":"default","dev":"other","table":20000}]`), nil
				default:
					return []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.2","prefixlen":24},{"family":"inet6","local":"2001:db8::2","prefixlen":64}]},{"ifname":"lo","flags":["LOOPBACK"],"addr_info":[{"family":"inet","local":"127.0.0.1"}]}]`), nil
				}
			}}
			err := s.inspect()
			if custom {
				if err == nil {
					t.Fatal("custom policy accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.table != "20001" || !reflect.DeepEqual(s.families[0].addresses, []string{"192.0.2.2/32"}) || !reflect.DeepEqual(s.families[1].addresses, []string{"2001:db8::2/128"}) {
				t.Fatalf("unexpected snapshot: %+v", s)
			}
		})
	}
}

func TestNetworkRollback(t *testing.T) {
	var commands []string
	s := &networkSession{run: func(args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if strings.Contains(command, "fail") {
			return nil, fmt.Errorf("injected failure")
		}
		return nil, nil
	}}
	if err := s.add("-4", "route", "add", "table", "20000", "default", "dev", "vpn0"); err != nil {
		t.Fatal(err)
	}
	if err := s.add("-4", "rule", "add", "pref", "10000", "lookup", "main"); err != nil {
		t.Fatal(err)
	}
	if err := s.add("-6", "rule", "add", "fail"); err == nil {
		t.Fatal("expected failure")
	}
	s.cleanup()
	s.cleanup()
	want := []string{"-4 rule del pref 10000 lookup main", "-4 route del table 20000 default dev vpn0"}
	if !reflect.DeepEqual(commands[3:], want) {
		t.Fatalf("cleanup: %v", commands)
	}
}

func TestConfigPolicyRouting(t *testing.T) {
	out, _ := parseVLESS("vless://id@127.0.0.1:443?security=none", false)
	data, err := makeConfig(out, options{all: true, tun: "vpn0", mtu: 1500})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds  []struct{ Settings map[string]any }
		Outbounds []struct {
			StreamSettings struct{ Sockopt struct{ Mark int } }
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Inbounds[0].Settings["autoSystemRoutingTable"]; ok {
		t.Fatal("Xray must not install routes")
	}
	for _, out := range cfg.Outbounds {
		if out.StreamSettings.Sockopt.Mark != bypassMark {
			t.Fatal("missing outbound bypass mark")
		}
	}
}

func echoListener(t *testing.T, network, address string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln
}
func echoPacketListener(t *testing.T, network, address string) {
	t.Helper()
	c, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo(buf[:n], addr)
		}
	}()
}

func exchange(c net.Conn) error {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	var buf [4]byte
	_, err := io.ReadFull(c, buf[:])
	if err == nil && string(buf[:]) != "ping" {
		return fmt.Errorf("unexpected echo %q", buf)
	}
	return err
}

// Runs only in a child namespace created by the integration test.
func TestRoutingPeer(t *testing.T) {
	if os.Getenv("VWAN_ROUTING_PEER") != "1" {
		t.Skip("integration helper")
	}
	fmt.Println("boot")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		command := scanner.Text()
		if command == "start" {
			echoListener(t, "tcp4", "0.0.0.0:19001")
			echoListener(t, "tcp6", "[::]:19001")
			echoPacketListener(t, "udp4", "0.0.0.0:19001")
			echoPacketListener(t, "udp6", "[::]:19001")
			fmt.Println("ready")
		} else if strings.HasPrefix(command, "dial ") {
			target := strings.TrimPrefix(command, "dial ")
			host, _, _ := net.SplitHostPort(target)
			source := "198.51.100.10"
			if strings.Contains(host, ":") {
				source = "2001:db8:2::10"
			}
			dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
			c, err := dialer.Dial("tcp", target)
			if err == nil {
				err = exchange(c)
				c.Close()
			}
			if err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("ok")
			}
		}
	}
}

// A subprocess is necessary because runCore owns the process signal handlers.
func TestWANHelper(t *testing.T) {
	if os.Getenv("VWAN_RUN_HELPER") != "1" {
		t.Skip("integration helper")
	}
	os.Args = []string{"vless-wan", "up", "--all", "--tun", "vpn0", "vless://00000000-0000-4000-8000-000000000000@198.51.100.10:19002?security=none&type=tcp"}
	if err := realMain(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRoutingIntegration(t *testing.T) {
	if os.Getenv("VWAN_ROUTING_TEST") != "1" {
		t.Skip("run make integration as root")
	}
	// Require a fresh namespace. Never run this test against the host network.
	var interfaces []interfaceInfo
	data, err := runIP("-j", "address", "show")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &interfaces); err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("integration test requires an empty network namespace")
	}
	ip := func(args ...string) {
		t.Helper()
		if _, err := runIP(args...); err != nil {
			t.Fatal(err)
		}
	}
	peer := exec.Command("unshare", "-n", os.Args[0], "-test.run=^TestRoutingPeer$")
	peer.Env = append(os.Environ(), "VWAN_ROUTING_PEER=1")
	stdin, _ := peer.StdinPipe()
	stdout, _ := peer.StdoutPipe()
	peer.Stderr = os.Stderr
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); peer.Process.Kill(); peer.Wait() })
	scanner := bufio.NewScanner(stdout)
	response := func(want string) {
		t.Helper()
		if !scanner.Scan() || scanner.Text() != want {
			t.Fatalf("peer: got %q, want %q", scanner.Text(), want)
		}
	}
	response("boot")
	ip("link", "set", "lo", "up")
	ip("link", "add", "real0", "type", "veth", "peer", "name", "peer0")
	ip("link", "set", "peer0", "netns", fmt.Sprint(peer.Process.Pid))
	ip("link", "set", "real0", "up")
	ip("addr", "add", "192.0.2.2/24", "dev", "real0")
	ip("-6", "addr", "add", "2001:db8:1::2/64", "dev", "real0", "nodad")
	ip("route", "add", "default", "via", "192.0.2.1")
	ip("-6", "route", "add", "default", "via", "2001:db8:1::1")
	peerIP := func(args ...string) {
		t.Helper()
		cmd := exec.Command("nsenter", append([]string{"-t", fmt.Sprint(peer.Process.Pid), "-n", "ip"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("peer ip: %v: %s", err, out)
		}
	}
	peerIP("link", "set", "lo", "up")
	peerIP("link", "set", "peer0", "up")
	peerIP("addr", "add", "192.0.2.1/24", "dev", "peer0")
	peerIP("addr", "add", "198.51.100.10/32", "dev", "lo")
	peerIP("addr", "add", "198.51.100.11/32", "dev", "lo")
	peerIP("-6", "addr", "add", "2001:db8:1::1/64", "dev", "peer0", "nodad")
	peerIP("-6", "addr", "add", "2001:db8:2::10/128", "dev", "lo", "nodad")
	fmt.Fprintln(stdin, "start")
	response("ready")
	echoListener(t, "tcp4", "192.0.2.2:19000")
	echoListener(t, "tcp6", "[2001:db8:1::2]:19000")
	existing := map[string]net.Conn{}
	for _, dst := range []string{"198.51.100.10:19001", "[2001:db8:2::10]:19001"} {
		c, err := net.DialTimeout("tcp", dst, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		existing[dst] = c
		if err := exchange(c); err != nil {
			t.Fatal(err)
		}
	}
	before4, _ := runIP("-j", "-4", "route", "show", "table", "main")
	before6, _ := runIP("-j", "-6", "route", "show", "table", "main")
	s, err := prepareNetwork(options{all: true, tun: "vpn0", excludeRoutes: listFlag{"198.51.100.11/32"}}, runIP)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := prepareNetwork(s.o, runIP); err == nil {
		t.Fatal("second instance accepted")
	}
	// Dummy device exercises the routing manager without requiring an external VPN.
	ip("link", "add", "vpn0", "type", "dummy")
	ip("link", "set", "vpn0", "up")
	ip("addr", "add", "172.19.0.1/30", "dev", "vpn0")
	ip("-6", "addr", "add", "fdfe:dcba:9876::1/126", "dev", "vpn0", "nodad")
	main4, _ := runIP("-j", "-4", "route", "show", "table", "main")
	main6, _ := runIP("-j", "-6", "route", "show", "table", "main")
	if err := s.activate(); err != nil {
		t.Fatal(err)
	}
	for dst, c := range existing {
		if err := exchange(c); err != nil {
			t.Fatalf("existing %s: %v", dst, err)
		}
	}
	for _, dst := range []string{"192.0.2.2:19000", "[2001:db8:1::2]:19000"} {
		fmt.Fprintln(stdin, "dial", dst)
		response("ok")
	}
	for _, tc := range []struct{ network, dst, source string }{{"tcp4", "198.51.100.10:19001", "192.0.2.2"}, {"tcp6", "[2001:db8:2::10]:19001", "2001:db8:1::2"}} {
		d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.source)}}
		c, err := d.Dial(tc.network, tc.dst)
		if err != nil {
			t.Fatal(err)
		}
		if err := exchange(c); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	for _, tc := range []struct{ flag, dst, source string }{{"-4", "198.51.100.10", "172.19.0.1"}, {"-6", "2001:db8:2::10", "fdfe:dcba:9876::1"}} {
		out, err := runIP(tc.flag, "route", "get", tc.dst)
		if err != nil || !strings.Contains(string(out), "dev vpn0") || !strings.Contains(string(out), "src "+tc.source) {
			t.Fatalf("VPN route: %s: %v", out, err)
		}
		out, err = runIP(tc.flag, "route", "get", tc.dst, "mark", fmt.Sprint(bypassMark))
		if err != nil || !strings.Contains(string(out), "dev real0") {
			t.Fatalf("bypass route: %s: %v", out, err)
		}
		c, err := net.Dial("udp", net.JoinHostPort(tc.dst, "19001"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(c.LocalAddr().String(), tc.source+":") && !strings.HasPrefix(c.LocalAddr().String(), "["+tc.source+"]:") {
			t.Fatalf("wrong source: %s", c.LocalAddr())
		}
		c.Close()
	}
	c, err := net.DialTimeout("tcp", "198.51.100.11:19001", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchange(c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	after4, _ := runIP("-j", "-4", "route", "show", "table", "main")
	after6, _ := runIP("-j", "-6", "route", "show", "table", "main")
	if string(main4) != string(after4) || string(main6) != string(after6) {
		t.Fatal("main routing table changed")
	}
	s.cleanup()
	if len(s.undo) != 0 {
		t.Fatal("incomplete cleanup")
	}
	ip("link", "del", "vpn0")
	after4, _ = runIP("-j", "-4", "route", "show", "table", "main")
	after6, _ = runIP("-j", "-6", "route", "show", "table", "main")
	if string(before4) != string(after4) || string(before6) != string(after6) {
		t.Fatal("routes not restored")
	}
	// Retry activation and force a failure at every mutation to verify rollback.
	ip("link", "add", "vpn0", "type", "dummy")
	ip("link", "set", "vpn0", "up")
	ip("addr", "add", "172.19.0.1/30", "dev", "vpn0")
	ip("-6", "addr", "add", "fdfe:dcba:9876::1/126", "dev", "vpn0", "nodad")
	for failure := 0; failure < 20; failure++ {
		count := 0
		s.run = func(args ...string) ([]byte, error) {
			if len(args) > 2 && args[2] == "add" {
				count++
				if count == failure+1 {
					return nil, fmt.Errorf("injected mutation failure")
				}
			}
			return runIP(args...)
		}
		err := s.activate()
		s.cleanup()
		if len(s.undo) != 0 {
			t.Fatal("rollback failed")
		}
		if err == nil {
			break
		}
		if failure == 19 {
			t.Fatal("never reached successful activation")
		}
	}

	s.run = runIP
	s.o.all = false
	s.o.routes = listFlag{"198.51.100.10/32", "2001:db8:2::10/128"}
	if err := s.activate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ flag, dst, dev string }{{"-4", "198.51.100.10", "vpn0"}, {"-4", "203.0.113.1", "real0"}, {"-6", "2001:db8:2::10", "vpn0"}, {"-6", "2001:db8:3::10", "real0"}} {
		out, err := runIP(tc.flag, "route", "get", tc.dst)
		if err != nil || !strings.Contains(string(out), "dev "+tc.dev) {
			t.Fatalf("selective route: %s: %v", out, err)
		}
	}
	s.close()
	ip("link", "del", "vpn0")
	// Exercise the embedded Xray on both ends, with no public network dependency.
	core, err := coreFiles.ReadFile("core/xray")
	if errors.Is(err, os.ErrNotExist) {
		if os.Getenv("VWAN_REQUIRE_XRAY") == "1" {
			t.Fatal("embedded Xray is required")
		}
		t.Log("embedded Xray absent; skipping end-to-end portion")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(core) < 1024*1024 {
		if os.Getenv("VWAN_REQUIRE_XRAY") == "1" {
			t.Fatal("embedded Xray is missing or incomplete")
		}
		t.Log("embedded Xray absent; skipping end-to-end portion")
		return
	}
	dir := t.TempDir()
	corePath := filepath.Join(dir, "xray")
	configPath := filepath.Join(dir, "server.json")
	if err := os.WriteFile(corePath, core, 0700); err != nil {
		t.Fatal(err)
	}
	config := `{"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":19002,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"00000000-0000-4000-8000-000000000000"}]}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["198.51.100.10/32","2001:db8:2::10/128"]}]}}]}`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	server := exec.Command("nsenter", "-t", fmt.Sprint(peer.Process.Pid), "-n", corePath, "run", "-c", configPath)
	server.Stdout = os.Stderr
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "198.51.100.10:19002", 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Xray server did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	logPath := filepath.Join(dir, "client.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	client := exec.Command(os.Args[0], "-test.run=^TestWANHelper$")
	client.Env = append(os.Environ(), "VWAN_RUN_HELPER=1")
	client.Stdout = logFile
	client.Stderr = logFile
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			client.Process.Kill()
			client.Wait()
		}
		data, _ := os.ReadFile(logPath)
		if t.Failed() {
			t.Logf("Xray client: %s", data)
		}
	}()
	deadline = time.Now().Add(8 * time.Second)
	for {
		out, err := runIP("-4", "route", "get", "198.51.100.10")
		if err == nil && strings.Contains(string(out), "dev vpn0") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("VPN client did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}

	for _, dst := range []string{"198.51.100.10:19001", "[2001:db8:2::10]:19001"} {
		c, err := net.DialTimeout("tcp", dst, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(c.LocalAddr().String(), "172.19.0.1") && !strings.Contains(c.LocalAddr().String(), "fdfe:dcba:9876::1") {
			t.Fatalf("expected TUN source, got %s", c.LocalAddr())
		}
		if err := exchange(c); err != nil {
			t.Fatalf("end-to-end VLESS %s: %v", dst, err)
		}
		c.Close()
	}

	for _, dst := range []string{"198.51.100.10:19001", "[2001:db8:2::10]:19001"} {
		c, err := net.Dial("udp", dst)
		if err != nil {
			t.Fatal(err)
		}
		if err := exchange(c); err != nil {
			t.Fatalf("end-to-end UDP %s: %v", dst, err)
		}
		c.Close()
	}
	for dst, c := range existing {
		if err := exchange(c); err != nil {
			t.Fatalf("existing TCP during real VPN %s: %v", dst, err)
		}
	}
	for _, dst := range []string{"192.0.2.2:19000", "[2001:db8:1::2]:19000"} {
		fmt.Fprintln(stdin, "dial", dst)
		response("ok")
	}
	if err := client.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = client.Wait()
	stopped = true
	if err != nil {
		t.Fatalf("VPN shutdown: %v", err)
	}
	for _, flag := range []string{"-4", "-6"} {
		out, err := runIP(flag, "rule", "show")
		if err != nil || strings.Contains(string(out), "20000") || strings.Contains(string(out), "10000:") {
			t.Fatalf("stale rules: %s: %v", out, err)
		}
	}

}
