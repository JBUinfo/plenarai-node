package security

import (
	"runtime"
	"sync"
	"time"
)

var (
	sensitiveBuffers [][]byte
	mu               sync.Mutex
)

// TrackSensitiveBuffer registers a byte slice for periodic zeroing.
// Call this for any buffer containing decrypted content.
func TrackSensitiveBuffer(buf []byte) {
	mu.Lock()
	defer mu.Unlock()
	sensitiveBuffers = append(sensitiveBuffers, buf)
}

// ScrubAll zeros all tracked sensitive buffers and releases them.
func ScrubAll() {
	mu.Lock()
	defer mu.Unlock()
	for _, buf := range sensitiveBuffers {
		for i := range buf {
			buf[i] = 0
		}
	}
	sensitiveBuffers = nil
	runtime.GC() // encourage garbage collection of zeroed data
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
