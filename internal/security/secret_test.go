package security

import "testing"

func TestDoSecretRunsCallback(t *testing.T) {
	runs := 0
	DoSecret(func() {
		runs++
	})
	if runs != 1 {
		t.Fatalf("DoSecret executed callback %d times; want 1", runs)
	}
}

func TestTrackedBufferCleanupZerosAndReleases(t *testing.T) {
	buf := []byte("sensitive")
	release := TrackSensitiveBuffer(buf)
	release()
	release() // cleanup must be idempotent

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d was not zeroed", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sensitiveBuffers) != 0 {
		t.Fatalf("tracked buffers were not released: %d remain", len(sensitiveBuffers))
	}
}

func TestScrubAllZerosTrackedBuffers(t *testing.T) {
	buf := []byte("sensitive")
	_ = TrackSensitiveBuffer(buf)
	ScrubAll()

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d was not zeroed", i)
		}
	}
}
