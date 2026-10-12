// Test-only separate client/node process; not part of the shipped CLI.
package main

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"github.com/plenarai/cli/internal/auth"
	"github.com/plenarai/cli/internal/config"
	"github.com/plenarai/cli/internal/inference"
	"github.com/plenarai/cli/internal/opaquechat"
	"github.com/plenarai/cli/internal/secureworker"
	"os"
	"strings"
)

type input struct {
	Backup, Password                                                           []byte
	Mode, Server, Token, Node, Pin, Conversation, Text, Second, Answer, Expect string
	Private                                                                    []byte
	Raw                                                                        json.RawMessage
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	if in.Mode == "node" {
		key, err := ecdh.X25519().NewPrivateKey(in.Private)
		if err != nil {
			panic(err)
		}
		out, err := secureworker.ProcessOpaque(context.Background(), key, in.Raw, "test system prompt", func(ctx context.Context, msg []inference.Message, opt inference.GenerationOptions) (string, inference.Usage, error) {
			// The client frames the current message with its exchange number and
			// coverage note; the typed text must still arrive intact at the end.
			if last := msg[len(msg)-1].Content; len(msg) < 2 || last != in.Expect && !strings.HasSuffix(last, "] "+in.Expect) {
				return "", inference.Usage{}, fmt.Errorf("wrong provider context")
			}
			return in.Answer, inference.Usage{PromptTokens: 1}, nil
		})
		if err != nil {
			panic(err)
		}
		json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	config.ServerURL = in.Server
	if err := auth.SaveTokens(&auth.TokenPair{AccessToken: in.Token, RefreshToken: "test-only"}); err != nil {
		panic(err)
	}
	owner, err := opaquechat.Owner()
	if err != nil {
		panic(err)
	}
	v, err := opaquechat.OpenVault()
	if err != nil {
		panic(err)
	}
	defer v.Close()
	if in.Mode == "export" {
		data, e := v.Export(in.Password)
		if e != nil {
			panic(e)
		}
		json.NewEncoder(os.Stdout).Encode(data)
		return
	}
	if in.Mode == "restore" {
		if e := v.Import(in.Backup, in.Password); e != nil {
			panic(e)
		}
	}
	var s *opaquechat.Session
	if in.Conversation == "" {
		p, e := opaquechat.GetProvider(in.Node, in.Pin)
		if e != nil {
			panic(e)
		}
		s, err = opaquechat.Create(v, owner, p, opaquechat.Archive{Title: "TITLE-PLAINTEXT-CANARY"})
	} else {
		s, err = opaquechat.Resume(v, owner, in.Conversation)
	}
	if err != nil {
		panic(err)
	}
	if in.Mode == "restore" || in.Mode == "inspect" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"messages": len(s.Messages)})
		return
	}
	if in.Mode == "transfer" {
		p, e := opaquechat.GetProvider(in.Node, in.Pin)
		if e != nil {
			panic(e)
		}
		s, e = s.Transfer(p, "TRANSFER-TITLE-CANARY")
		if e != nil {
			panic(e)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"conversation": s.Entry.Create.ConversationID, "messages": len(s.Messages)})
		return
	}
	answer, err := s.Send(in.Text, 1)
	if err != nil {
		panic(err)
	}
	if in.Second != "" {
		answer, err = s.Send(in.Second, 1)
		if err != nil {
			panic(err)
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"conversation": s.Entry.Create.ConversationID, "answer": answer, "messages": len(s.Messages)})
}
