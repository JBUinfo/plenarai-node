package security

import (
	"runtime"
	"sync"
	"time"
)

var (
	sensitiveBuffers = make(map[uint64][]byte)
	nextBufferID     uint64
	mu               sync.Mutex
)

// TrackSensitiveBuffer registers a byte slice for periodic zeroing.
// Call the returned cleanup function as soon as the buffer is no longer needed.
func TrackSensitiveBuffer(buf []byte) func() {
	mu.Lock()
	nextBufferID++
	id := nextBufferID
	sensitiveBuffers[id] = buf
	mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			defer mu.Unlock()
			if tracked, ok := sensitiveBuffers[id]; ok {
				zeroBytes(tracked)
				delete(sensitiveBuffers, id)
			}
		})
	}
}

// ScrubAll zeros all tracked sensitive buffers and releases them.
func ScrubAll() {
	mu.Lock()
	defer mu.Unlock()
	for id, buf := range sensitiveBuffers {
		zeroBytes(buf)
		delete(sensitiveBuffers, id)
	}
	runtime.GC() // encourage garbage collection of zeroed data
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// StartPeriodicScrub runs ScrubAll every interval as a safety net.
// Even if a buffer was missed, it gets zeroed eventually.
func StartPeriodicScrub(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ScrubAll()
		}
	}()
}
