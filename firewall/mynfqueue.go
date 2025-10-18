package main

import (
	//"fmt"
	"context"
	"sync"

	"github.com/florianl/go-nfqueue"
)

/*
mynfqueue extends nfqueue.Nfqueue with a simple user-space queue
Usage:
nf, err := NewMynfqueue(&config) instead of nf, err := nfqueue.Open(&config)

Methods:
PeekQueue - returns a copy of the current queue (See how this works!)
Len - Returns length of queue
*/
type mynfqueue struct {
	*nfqueue.Nfqueue                     // embed the original nfqueue type
	packetQueue      []nfqueue.Attribute // user-space copy of packets
	mu               sync.Mutex          // probably redundant
	maxQueueLen      int                 // limit
}

// New creates a new mynfqueue with the given config and max length
func NewMynfqueue(config *nfqueue.Config) (*mynfqueue, error) {
	nfq, err := nfqueue.Open(config)
	if err != nil {
		return nil, err
	}

	return &mynfqueue{
		Nfqueue:     nfq,
		packetQueue: make([]nfqueue.Attribute, 0, config.MaxQueueLen),
		maxQueueLen: int(config.MaxQueueLen),
	}, nil
}

// PeekQueue returns a snapshot of the current queue
func (m *mynfqueue) PeekQueue() []nfqueue.Attribute {
	m.mu.Lock()
	defer m.mu.Unlock()
	copyQueue := make([]nfqueue.Attribute, len(m.packetQueue))
	copy(copyQueue, m.packetQueue)
	return copyQueue
}

// Len returns the number of packets currently in the queue
func (m *mynfqueue) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.packetQueue)
}

// removePacketByID removes a packet from the queue by its ID
func (m *mynfqueue) removePacketByID(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, attr := range m.packetQueue {
		if attr.PacketID != nil && *attr.PacketID == id {
			// Remove the packet from the queue
			m.packetQueue = append(m.packetQueue[:i], m.packetQueue[i+1:]...)
			return
		}
	}
}

// Overrides

func (m *mynfqueue) RegisterWithErrorFunc(ctx context.Context, fn nfqueue.HookFunc, errfn nfqueue.ErrorFunc) error {
	//Wrapper function
	wrappedFn := func(a nfqueue.Attribute) int {
		// Add packet to queue
		if len(m.packetQueue) < m.maxQueueLen {
			m.packetQueue = append(m.packetQueue, a)
		}
		return fn(a)
	}

	return m.Nfqueue.RegisterWithErrorFunc(ctx, wrappedFn, errfn)

}

// SetVerdict wraps the original method and removes the packet from the user-space queue
// Important: No other set verdicts are overwritten
func (m *mynfqueue) SetVerdict(id uint32, verdict int) error {
	m.removePacketByID(id)
	return m.Nfqueue.SetVerdict(id, verdict)
}
