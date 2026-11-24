package validator

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	lookupsPerMinute = 10
	maxTrackedPeers  = 1024
)

// A failed or in-flight cache miss occupies one slot for the current minute.
// Reserving before I/O also bounds parallel misses. Successful checks refund the slot.
type lookupBudget struct {
	mu    sync.Mutex
	until time.Time
	used  map[netip.Addr]int
}

// Only a configured proxy may assert the address of its preceding hop.
func lookupPeer(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote, _ := netip.ParseAddrPort(r.RemoteAddr)
	socket := remote.Addr().Unmap()
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(trusted) == 0 || len(forwarded) == 0 {
		return socket
	}
	peer := socket
	chain := strings.Join(forwarded, ",")
	for slices.ContainsFunc(trusted, func(network netip.Prefix) bool { return network.Contains(peer) }) {
		comma := strings.LastIndexByte(chain, ',')
		previous, err := netip.ParseAddr(strings.TrimSpace(chain[comma+1:]))
		if err != nil || previous.Zone() != "" {
			return socket
		}
		peer = previous.Unmap()
		if comma < 0 {
			break
		}
		chain = chain[:comma]
	}
	return peer
}

func (b *lookupBudget) reserve(peer netip.Addr, now time.Time) (refund func(), retrySeconds int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !now.Before(b.until) {
		b.until = now.Add(time.Minute)
		b.used = make(map[netip.Addr]int)
	}
	used := b.used
	if used[peer] >= lookupsPerMinute || (used[peer] == 0 && len(used) >= maxTrackedPeers) {
		return nil, int((b.until.Sub(now) + time.Second - 1) / time.Second)
	}
	used[peer]++
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		used[peer]--
		if used[peer] == 0 {
			delete(used, peer)
		}
	}, 0
}
