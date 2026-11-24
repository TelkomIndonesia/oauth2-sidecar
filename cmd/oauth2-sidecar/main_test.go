package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestShutdownDrainsActiveRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "done")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- serve(ctx, srv, ln) }()
	response := make(chan string, 1)
	go func() {
		client := http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String())
		if err != nil {
			response <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			response <- err.Error()
			return
		}
		response <- string(body)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-stopped:
		t.Fatalf("shutdown returned before handler finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	if got := <-response; got != "done" {
		t.Fatalf("response: %q", got)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}

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
