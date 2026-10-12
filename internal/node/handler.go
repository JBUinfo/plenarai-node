package node

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"

	"github.com/plenarai/cli/internal/opaque"
	"github.com/plenarai/cli/internal/securework"
	"github.com/plenarai/cli/internal/secureworker"
	"github.com/plenarai/cli/logger"
)

// handleQuestion is the exterior relay: it never receives answer plaintext.
func handleQuestion(conn *SafeConn, privKey *ecdh.PrivateKey, rawData json.RawMessage, eng *engine, promptTemplate string) {
	var metadata struct {
		WorkKind       string `json:"work_kind"`
		DeadlineUnixMs int64  `json:"deadline_unix_ms"`
	}
	if err := json.Unmarshal(rawData, &metadata); err != nil {
		logger.Log.Warn("secure-worker rejected malformed question", "error", err)
		return
	}
	var jobID string
	if metadata.WorkKind == opaque.WorkKind {
		result, e := secureworker.ProcessOpaque(context.Background(), privKey, rawData, promptTemplate, eng.completeMessagesWithUsage)
		if e != nil {
			logger.Log.Warn("encrypted conversation job rejected")
			return
		}
		data, e := json.Marshal(map[string]any{"type": "opaque_response", "data": result})
		if e == nil {
			e = conn.WriteMessage(websocket.TextMessage, data)
		}
		if e != nil {
			logger.Log.Warn("encrypted conversation relay failed")
		}
		return
	}
	var envelope securework.Envelope
	var err error
	if metadata.WorkKind == securework.WorkKindConversationTurn {
		deadline := time.Now().Add(55 * time.Second) // older coordinators
		if metadata.DeadlineUnixMs > 0 {
			deadline = time.UnixMilli(metadata.DeadlineUnixMs)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		jobID, envelope, err = secureworker.ProcessConversation(ctx, privKey, rawData, promptTemplate, eng.completeMessages)
	} else {
		jobID, envelope, err = secureworker.ProcessQuestionWithError(privKey, rawData, promptTemplate, eng.completeSafe)
	}
	if err != nil {
		logger.Log.Warn("secure-worker rejected question", "error", err)
		return
	}
	data, err := json.Marshal(map[string]any{"type": "response", "data": envelope})
	if err != nil {
		logger.Log.Error("failed to encode response envelope", "error", err)
		return
	}
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		logger.Log.Error("failed to relay response envelope", "error", err)
		return
	}
	logger.Log.Info("encrypted response relayed", "question_id", jobID)
}
