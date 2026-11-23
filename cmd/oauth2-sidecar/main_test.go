package main

import (
	"net"
	"testing"
)

func TestDynamicCacheListenerAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:", "127.0.0.1:0", "127.0.0.1:00"} {
		t.Run(addr, func(t *testing.T) {
			seen := map[string]bool{}
			for i := 0; i < 2; i++ {
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				key := cacheListenerAddress(addr, ln)
				if key != ln.Addr().String() || seen[key] {
					t.Fatalf("unexpected cache address %q", key)
				}
				seen[key] = true
			}
		})
	}
}
