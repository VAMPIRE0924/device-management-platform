package nodeadapter

import "testing"

func TestTaskRefUsesTypeAndIDAsIdentity(t *testing.T) {
	portForward, err := (TaskRef{Type: "portForward", ID: 1}).Key()
	if err != nil {
		t.Fatal(err)
	}
	socks, err := (TaskRef{Type: "socks5", ID: 1}).Key()
	if err != nil {
		t.Fatal(err)
	}
	if portForward != "portForward:1" || socks != "socks5:1" || portForward == socks {
		t.Fatalf("compound keys = %q and %q", portForward, socks)
	}
	for _, invalid := range []TaskRef{{Type: "udp", ID: 1}, {Type: "portForward", ID: 0}} {
		if _, err := invalid.Key(); err == nil {
			t.Fatalf("invalid task ref accepted: %#v", invalid)
		}
	}
}
