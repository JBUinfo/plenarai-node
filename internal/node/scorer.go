package node

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"

	"github.com/plenarai/cli/internal/secureworker"
	"github.com/plenarai/cli/logger"
)

// handleScoreRequest is the exterior relay: scores and candidate plaintext
// remain on the secure-worker side of the package boundary.
func handleScoreRequest(conn *SafeConn, privKey *ecdh.PrivateKey, rawData json.RawMessage, eng *engine) {
	var metadata struct {
		DeadlineUnixMs int64 `json:"deadline_unix_ms"`
	}
	_ = json.Unmarshal(rawData, &metadata)       // The worker validates the full request.
	deadline := time.Now().Add(25 * time.Second) // older coordinators
	if metadata.DeadlineUnixMs > 0 {
		deadline = time.UnixMilli(metadata.DeadlineUnixMs)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	jobID, envelope, err := secureworker.ProcessScoreWithContext(ctx, privKey, rawData, eng.complete, eng.completeMessages)
	if err != nil {
		logger.Log.Warn("secure-worker rejected score request", "error", err)
		return
	}
	data, err := json.Marshal(map[string]any{"type": "score_response", "data": envelope})
	if err != nil {
		logger.Log.Error("failed to encode score envelope", "error", err)
		return
	}
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		logger.Log.Error("failed to relay score envelope", "error", err)
		return
	}
	logger.Log.Info("encrypted scores relayed", "question_id", jobID)
}
