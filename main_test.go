package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParseReality(t *testing.T) {
	out, err := parseVLESS("vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=cdn.example.com&fp=chrome&pbk=abc&sid=01&type=grpc&serviceName=test", false)
	if err != nil {
		t.Fatal(err)
	}
	stream := out["streamSettings"].(map[string]any)
	tls := stream["realitySettings"].(map[string]any)
	if tls["serverName"] != "cdn.example.com" {
		t.Fatalf("bad TLS: %#v", tls)
	}
	if stream["grpcSettings"].(map[string]any)["serviceName"] != "test" {
		t.Fatal("bad grpc")
	}
}

func TestConfigModes(t *testing.T) {
	out, _ := parseVLESS("vless://id@example.com:443?security=tls", false)
	data, err := makeConfig(out, options{domains: listFlag{"example.org"}, routes: listFlag{"10.0.0.0/8"}, tun: "vw0", mtu: 1500})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	routing := cfg["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	if len(rules) != 2 || rules[1].(map[string]any)["outboundTag"] != "direct" {
		t.Fatalf("selective rules = %#v", rules)
	}
}

func TestBadCIDR(t *testing.T) {
	out, _ := parseVLESS("vless://id@example.com:443", false)
	_, err := makeConfig(out, options{routes: listFlag{"nope"}})
	if err == nil {
		t.Fatal("expected CIDR error")
	}
}

func TestSshuttleTargets(t *testing.T) {
	var routes, domains listFlag
	for _, target := range []string{"0/0", "::/0", "10.20.0.0/16", "example.org"} {
		if err := addTarget(target, &routes, &domains); err != nil {
			t.Fatal(err)
		}
	}
	if routes[0] != "0.0.0.0/0" || len(routes) != 3 || domains[0] != "example.org" {
		t.Fatalf("routes=%v domains=%v", routes, domains)
	}
}

func TestNameServer(t *testing.T) {
	host, port, err := parseNameServer("[2606:4700:4700::1111]:5353")
	if err != nil || host != "2606:4700:4700::1111" || port != 5353 {
		t.Fatalf("%s %d %v", host, port, err)
	}
}

func TestVLESSEncryption(t *testing.T) {
	out, err := parseVLESS("vless://id@example.com:443?encryption=mlkem768x25519plus.native.0rtt.secret", false)
	if err != nil {
		t.Fatal(err)
	}
	settings := out["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)[0].(map[string]any)
	user := vnext["users"].([]any)[0].(map[string]any)
	if user["encryption"] != "mlkem768x25519plus.native.0rtt.secret" {
		t.Fatal("encryption was not preserved")
	}
}

func TestKernelRoutes(t *testing.T) {
	got := kernelRoutes(options{routes: listFlag{"10.0.0.0/8"}})
	if len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("selective routes: %v", got)
	}
	got = kernelRoutes(options{routes: listFlag{"10.0.0.0/8"}, domains: listFlag{"example.org"}})
	if len(got) != 2 || got[0] != "0.0.0.0/0" || got[1] != "::/0" {
		t.Fatalf("domain routes: %v", got)
	}
	got = systemRoutes(options{all: true})
	if len(got) != 4 || got[0] != "0.0.0.0/1" || got[1] != "128.0.0.0/1" {
		t.Fatalf("system default routes: %v", got)
	}
}

func TestCapabilityEnabled(t *testing.T) {
	const netAdmin = 12
	if !capabilityEnabled("Name:\ttest\nCapEff:\t0000000000001000\n", netAdmin) {
		t.Fatal("CAP_NET_ADMIN should be enabled")
	}
	for _, status := range []string{
		"Name:\ttest\nCapEff:\t0000000000000000\n",
		"Name:\ttest\n",
		"CapEff:\tnot-hex\n",
	} {
		if capabilityEnabled(status, netAdmin) {
			t.Fatalf("CAP_NET_ADMIN should be disabled for %q", status)
		}
	}
}

func TestWaitForTUNReturnsWhenChildExits(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 23")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	signals := make(chan os.Signal)
	start := time.Now()
	err := waitForTUN(cmd, wait, signals, "vless-wan-test-does-not-exist")
	if err == nil || !strings.Contains(err.Error(), "exited before creating") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("child exit took too long to observe: %s", elapsed)
	}
}
