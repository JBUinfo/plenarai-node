package node

import (
	"crypto/ecdh"
	"encoding/json"

	"github.com/gorilla/websocket"

	"github.com/plenarai/cli/internal/crypto"
	"github.com/plenarai/cli/internal/security"
	"github.com/plenarai/cli/logger"
)

func handleQuestion(conn *SafeConn, privKey *ecdh.PrivateKey, rawData json.RawMessage, eng *engine, promptTemplate string) {
	var payload questionPayload
	if err := json.Unmarshal(rawData, &payload); err != nil {
		logger.Log.Error("failed to parse question payload", "error", err)
		return
	}

	if len(payload.EncryptedKey) == 0 {
		logger.Log.Warn("no encrypted key in question payload")
		return
	}

	plaintext, err := crypto.DecryptQuestion(privKey, payload.ServerPublicKey, payload.EncryptedKey, payload.EncryptedQuestion)
	if err != nil {
		logger.Log.Error("failed to decrypt question", "error", err)
		return
	}
	security.TrackSensitiveBuffer(plaintext)
	defer crypto.ZeroBytes(plaintext)

	logger.Log.Info("question received", "question_id", payload.QuestionID)

	answer := eng.complete(promptTemplate, string(plaintext))

	response := map[string]interface{}{
		"type": "response",
		"data": map[string]interface{}{
			"question_id":   payload.QuestionID,
			"response_text": answer,
		},
	}

	data, _ := json.Marshal(response)
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		logger.Log.Error("failed to send response", "error", err)
		return
	}

	logger.Log.Info("response sent", "question_id", payload.QuestionID)
}
