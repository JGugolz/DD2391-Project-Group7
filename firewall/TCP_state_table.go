package main

import (
	"net"
	"sync"
	"time"
)

///////////////////////////////////////////////////////////////////////////////
// TCP state machine definitions
///////////////////////////////////////////////////////////////////////////////

// TCPState represents the simplified TCP connection state used by the firewall.
// It’s intentionally close to RFC 793 semantics for teaching purposes.
type TCPState int

const (
	StateClosed TCPState = iota
	StateSynSent
	StateSynRecv
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateLastAck
	StateTimeWait
)

func (s TCPState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynRecv:
		return "SYN_RECV"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait1:
		return "FIN_WAIT1"
	case StateFinWait2:
		return "FIN_WAIT2"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateTimeWait:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}

///////////////////////////////////////////////////////////////////////////////
// Flow keys, entries, and the state table
///////////////////////////////////////////////////////////////////////////////

// FlowKey is a directional 5-tuple key (src→dst) for TCP flows.
type FlowKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// ConnEntry stores per-flow state, the origin direction, and last activity time.
type ConnEntry struct {
	State      TCPState
	Origin     FlowKey   // the direction that sent the first SYN (no ACK)
	HaveOrigin bool      // true once Origin is set
	LastSeen   time.Time // last packet time (for timeouts/GC)
}

// ip4 is a compact IPv4 key for per-IP counters/shuns.
type ip4 [4]byte

// windowCounter provides a simple fixed-window counter (start + count).
type windowCounter struct {
	start time.Time
	cnt   int
}

// StateTable holds all flows plus timeouts and flood-control knobs.
// It is safe for concurrent use.
type StateTable struct {
	mu  sync.Mutex
	tab map[FlowKey]*ConnEntry

	// Timeouts
	synTimeout         time.Duration
	establishedTimeout time.Duration
	finTimeout         time.Duration
	timeWaitTimeout    time.Duration

	// Flood control
	synPerIPLimit       int                    // max initial SYNs per IP per window
	synWindow           time.Duration          // SYN window size
	synBySrc            map[ip4]*windowCounter // per-IP SYN counters
	banned              map[ip4]time.Time      // temporary shuns (until time)
	banDuration         time.Duration          // shun period
	globalHalfOpenLimit int                    // cap on SYN_SENT+SYN_RECV across table
	rstPerIPLimit       int                    // per-IP RST limit per window
	rstWindow           time.Duration          // RST window size
	rstBySrc            map[ip4]*windowCounter // per-IP RST counters
}

///////////////////////////////////////////////////////////////////////////////
// Construction, helpers, and garbage collection
///////////////////////////////////////////////////////////////////////////////

// NewStateTable constructs a state table with sensible lab defaults and
// starts a periodic garbage collector.
func NewStateTable() *StateTable {
	st := &StateTable{
		tab: make(map[FlowKey]*ConnEntry),

		// Timeouts (tweak for your lab scale)
		synTimeout:         30 * time.Second,
		establishedTimeout: 5 * time.Minute,
		finTimeout:         60 * time.Second,
		timeWaitTimeout:    30 * time.Second,

		// Flood control defaults (tweak for your lab scale)
		synPerIPLimit:       50,
		synWindow:           1 * time.Second,
		synBySrc:            make(map[ip4]*windowCounter),
		banned:              make(map[ip4]time.Time),
		banDuration:         90 * time.Second,
		globalHalfOpenLimit: 2000,

		rstPerIPLimit: 50,
		rstWindow:     1 * time.Second,
		rstBySrc:      make(map[ip4]*windowCounter),
	}

	// Periodic GC of stale entries.
	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			st.gc()
		}
	}()

	return st
}

// b4 copies the first four bytes of an IP slice into a [4]byte for map keys.
func b4(ip []byte) [4]byte {
	var a [4]byte
	copy(a[:], ip[:4])
	return a
}

// ip4From converts a [4]byte into ip4.
func ip4From(b [4]byte) ip4 { return ip4(b) }

// isBanned reports whether src is currently shunned. If a ban expired, it
// removes the entry and returns false.
func (st *StateTable) isBanned(src ip4) bool {
	until, ok := st.banned[src]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(st.banned, src)
	return false
}

// bumpFixedWindow increments a per-key counter in a fixed time window and
// returns the current count within that window.
func (st *StateTable) bumpFixedWindow(m map[ip4]*windowCounter, key ip4, win time.Duration) int {
	now := time.Now()
	wc, ok := m[key]
	if !ok || now.Sub(wc.start) >= win {
		m[key] = &windowCounter{start: now, cnt: 1}
		return 1
	}
	wc.cnt++
	return wc.cnt
}

// halfOpenCount returns the number of SYN_SENT + SYN_RECV entries.
func (st *StateTable) halfOpenCount() int {
	n := 0
	for _, e := range st.tab {
		if e.State == StateSynSent || e.State == StateSynRecv {
			n++
		}
	}
	return n
}

// gc removes stale entries based on their state-specific timeouts.
func (st *StateTable) gc() {
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()

	for k, e := range st.tab {
		to := st.establishedTimeout
		switch e.State {
		case StateSynSent, StateSynRecv:
			to = st.synTimeout
		case StateFinWait1, StateFinWait2, StateCloseWait, StateLastAck:
			to = st.finTimeout
		case StateTimeWait:
			to = st.timeWaitTimeout
		}
		if now.Sub(e.LastSeen) > to {
			delete(st.tab, k)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Decision logic (state machine)
// Returns: accept?, reason, new/current state
///////////////////////////////////////////////////////////////////////////////

// Direction is kept for clarity if you extend logic later (currently unused).
type Direction int

const (
	DirOrigin Direction = iota
	DirReply
)

// Decide updates/consults the TCP state machine for the given 5-tuple + flags.
// It enforces the policy: new flows must start with SYN (no ACK); otherwise drop.
func (st *StateTable) Decide(
	srcIP [4]byte, dstIP [4]byte, srcPort, dstPort uint16,
	syn, ack, fin, rst bool,
) (accept bool, reason string, newState TCPState) {

	key := FlowKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}
	rev := FlowKey{SrcIP: dstIP, DstIP: srcIP, SrcPort: dstPort, DstPort: srcPort}
	now := time.Now()

	st.mu.Lock()
	defer st.mu.Unlock()

	// Find existing entry in either direction.
	e := st.tab[key]
	if e == nil {
		e = st.tab[rev]
	}

	// No entry yet: only allow initial SYN (no ACK) to create state.
	if e == nil {
		if syn && !ack {
			e = &ConnEntry{
				State:      StateSynSent,
				Origin:     key,
				HaveOrigin: true,
				LastSeen:   now,
			}
			st.tab[key] = e // store under the direction first observed
			return true, "new->SYN_SENT", e.State
		}
		return false, "no-state-not-SYN", StateClosed
	}

	// Determine if this packet is from the originator or the replier.
	dirIsOrigin := (e.Origin.SrcIP == key.SrcIP &&
		e.Origin.SrcPort == key.SrcPort &&
		e.Origin.DstIP == key.DstIP &&
		e.Origin.DstPort == key.DstPort)

	// State transitions (simplified but accurate for a lab).
	switch e.State {
	case StateSynSent:
		// Expect SYN+ACK from the reply side.
		if !dirIsOrigin && syn && ack {
			e.State = StateSynRecv
			e.LastSeen = now
			return true, "SYN_SENT->SYN_RECV", e.State
		}
		// Retransmits / simultaneous open: accept but keep state.
		e.LastSeen = now
		return true, "SYN_SENT(other)", e.State

	case StateSynRecv:
		// Final ACK from origin completes the handshake.
		if dirIsOrigin && ack && !syn {
			e.State = StateEstablished
			e.LastSeen = now
			return true, "SYN_RECV->ESTABLISHED", e.State
		}
		e.LastSeen = now
		return true, "SYN_RECV(other)", e.State

	case StateEstablished:
		// Immediate close on RST.
		if rst {
			delete(st.tab, key)
			delete(st.tab, rev)
			return true, "ESTABLISHED->CLOSED(RST)", StateClosed
		}
		// FIN initiates teardown.
		if fin {
			if dirIsOrigin {
				e.State = StateFinWait1
				e.LastSeen = now
				return true, "ESTABLISHED->FIN_WAIT1", e.State
			}
			e.State = StateCloseWait
			e.LastSeen = now
			return true, "ESTABLISHED->CLOSE_WAIT", e.State
		}
		// Normal data/ACKs.
		e.LastSeen = now
		return true, "ESTABLISHED(data/ack)", e.State

	case StateFinWait1:
		if !dirIsOrigin && ack && !fin {
			e.State = StateFinWait2
			e.LastSeen = now
			return true, "FIN_WAIT1->FIN_WAIT2", e.State
		}
		if !dirIsOrigin && fin {
			e.State = StateTimeWait
			e.LastSeen = now
			return true, "FIN_WAIT1->TIME_WAIT", e.State
		}
		e.LastSeen = now
		return true, "FIN_WAIT1(other)", e.State

	case StateFinWait2:
		if !dirIsOrigin && fin {
			e.State = StateTimeWait
			e.LastSeen = now
			return true, "FIN_WAIT2->TIME_WAIT", e.State
		}
		e.LastSeen = now
		return true, "FIN_WAIT2(other)", e.State

	case StateCloseWait:
		if dirIsOrigin && fin {
			e.State = StateLastAck
			e.LastSeen = now
			return true, "CLOSE_WAIT->LAST_ACK", e.State
		}
		e.LastSeen = now
		return true, "CLOSE_WAIT(other)", e.State

	case StateLastAck:
		if !dirIsOrigin && ack {
			delete(st.tab, key)
			delete(st.tab, rev)
			return true, "LAST_ACK->CLOSED", StateClosed
		}
		e.LastSeen = now
		return true, "LAST_ACK(other)", e.State

	case StateTimeWait:
		// Allow during TIME_WAIT; GC will remove later.
		e.LastSeen = now
		return true, "TIME_WAIT", e.State
	}

	// Fallback: accept and refresh.
	e.LastSeen = now
	return true, "default", e.State
}

///////////////////////////////////////////////////////////////////////////////
// Snapshot / dump (for the HTTP monitor)
///////////////////////////////////////////////////////////////////////////////

// ConnDump is a rendered connection entry for JSON/HTML.
type ConnDump struct {
	Key      FlowKeyDump `json:"key"`
	State    string      `json:"state"`
	LastSeen time.Time   `json:"last_seen"`
	IsOrigin bool        `json:"is_origin"`
}

// FlowKeyDump is a printable version of FlowKey with string IPs.
type FlowKeyDump struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
}

// Snapshot is a table snapshot for the monitor UI/JSON.
type Snapshot struct {
	Now         time.Time            `json:"now"`
	Total       int                  `json:"total"`
	HalfOpen    int                  `json:"half_open"`
	Counts      map[string]int       `json:"counts"`
	Entries     []ConnDump           `json:"entries"`
	SynBySrc    map[string]int       `json:"syn_by_src_per_window"`
	RstBySrc    map[string]int       `json:"rst_by_src_per_window"`
	BannedUntil map[string]time.Time `json:"banned_until"`

	// Config (handy to display on the page)
	SynPerIPLimit       int           `json:"syn_per_ip_limit"`
	SynWindow           time.Duration `json:"syn_window"`
	GlobalHalfOpenLimit int           `json:"global_half_open_limit"`
	RSTPerIPLimit       int           `json:"rst_per_ip_limit"`
	RSTWindow           time.Duration `json:"rst_window"`
	BanDuration         time.Duration `json:"ban_duration"`
}

func ipToStr(a [4]byte) string { return net.IP(a[:]).String() }

// Snapshot safely copies current table + counters for rendering/JSON.
func (st *StateTable) Snapshot() Snapshot {
	st.mu.Lock()
	defer st.mu.Unlock()

	s := Snapshot{
		Now:                 time.Now(),
		Counts:              map[string]int{},
		Entries:             make([]ConnDump, 0, len(st.tab)),
		SynBySrc:            map[string]int{},
		RstBySrc:            map[string]int{},
		BannedUntil:         map[string]time.Time{},
		SynPerIPLimit:       st.synPerIPLimit,
		SynWindow:           st.synWindow,
		GlobalHalfOpenLimit: st.globalHalfOpenLimit,
		RSTPerIPLimit:       st.rstPerIPLimit,
		RSTWindow:           st.rstWindow,
		BanDuration:         st.banDuration,
	}

	half := 0
	for k, e := range st.tab {
		if e.State == StateSynSent || e.State == StateSynRecv {
			half++
		}
		stateStr := e.State.String()
		s.Counts[stateStr]++
		s.Entries = append(s.Entries, ConnDump{
			Key: FlowKeyDump{
				SrcIP:   ipToStr(k.SrcIP),
				DstIP:   ipToStr(k.DstIP),
				SrcPort: k.SrcPort,
				DstPort: k.DstPort,
			},
			State:    stateStr,
			LastSeen: e.LastSeen,
			IsOrigin: (e.Origin == k),
		})
	}
	s.Total = len(st.tab)
	s.HalfOpen = half

	for ip, wc := range st.synBySrc {
		s.SynBySrc[net.IP(ip[:]).String()] = wc.cnt
	}
	for ip, wc := range st.rstBySrc {
		s.RstBySrc[net.IP(ip[:]).String()] = wc.cnt
	}
	for ip, until := range st.banned {
		s.BannedUntil[net.IP(ip[:]).String()] = until
	}

	return s
}

// FormatTimes converts all timestamps in the snapshot into local, human-readable times
// (drop sub-second precision).
func (s *Snapshot) FormatTimes() {
	loc := time.Local
	s.Now = s.Now.In(loc).Truncate(time.Second)
	for i := range s.Entries {
		s.Entries[i].LastSeen = s.Entries[i].LastSeen.In(loc).Truncate(time.Second)
	}
	for ip, t := range s.BannedUntil {
		s.BannedUntil[ip] = t.In(loc).Truncate(time.Second)
	}
}
