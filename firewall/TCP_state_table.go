package main

import (
	"sync"
	"time"
)

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

// FlowKey is directional (src->dst)
type FlowKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

type ConnEntry struct {
	State      TCPState
	Origin     FlowKey
	HaveOrigin bool
	LastSeen   time.Time
}

type StateTable struct {
	mu  sync.Mutex
	tab map[FlowKey]*ConnEntry
	// Timeouts
	synTimeout         time.Duration
	establishedTimeout time.Duration
	finTimeout         time.Duration
	timeWaitTimeout    time.Duration
}

func NewStateTable() *StateTable {
	st := &StateTable{ // TODO: Move duration to config file
		tab:                make(map[FlowKey]*ConnEntry),
		synTimeout:         30 * time.Second,
		establishedTimeout: 5 * time.Minute,
		finTimeout:         60 * time.Second,
		timeWaitTimeout:    30 * time.Second,
	}
	// GC sweeper ?
	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			st.gc()
		}
	}()
	return st
}

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

func b4(ip []byte) [4]byte {
	var a [4]byte
	copy(a[:], ip[:4])
	return a
}

type Direction int

const (
	DieOrigin Direction = iota
	DirReply
)

func (st *StateTable) Decide(
	srcIp [4]byte, dstIP [4]byte, srcPort, dstPort uint16,
	syn, ack, fin, rst bool,
) (accept bool, reason string, newState TCPState) {

	key := FlowKey{SrcIP: srcIp, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}
	rev := FlowKey{SrcIP: dstIP, DstIP: srcIp, SrcPort: dstPort, DstPort: srcPort}
	now := time.Now()

	st.mu.Lock()
	defer st.mu.Unlock()

	e := st.tab[key]
	if e == nil {
		e = st.tab[rev]
	}

	// No entry yet
	if e == nil {
		if syn && !ack {
			e = &ConnEntry{
				State:      StateSynSent,
				Origin:     key,
				HaveOrigin: true,
				LastSeen:   now,
			}
			st.tab[key] = e
			return true, "new->SYN_SENT", e.State
		}
		return false, "no-state-not-SYN", StateClosed
	}

	// Determine if this packet isi from the originator or the replier
	dirIsOrigin := (e.Origin.SrcIP == key.SrcIP &&
		e.Origin.SrcPort == key.SrcPort &&
		e.Origin.DstIP == key.DstIP &&
		e.Origin.DstPort == key.DstPort)

	switch e.State {
	case StateSynSent:
		// Expect SYN+ACK from reply side
		if !dirIsOrigin && syn && ack {
			e.State = StateSynRecv
			e.LastSeen = now
			return true, "SYN_SENT->SYN_RECV", e.State
		}
		e.LastSeen = now
		return true, "SYN_SENT(other)", e.State

	case StateSynRecv:
		// Final ACK from origin completes handshake
	}
}
