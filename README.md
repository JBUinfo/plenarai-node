# PlenarAI CLI

Command-line client for [PlenarAI](https://plenarai.com): ask questions to a network of independently operated AI nodes, or run your own node and earn credits by answering — or by judging other nodes' answers.

- **Questioner:** pay credits, several models compete, judge consensus picks the best answer.
- **Responder:** answer questions with a local model on your own hardware.
- **Judge (`--score-only`):** evaluate anonymised answers without ever responding.
- **Directed mode:** address one specific node with `--node-id` (95/5 payout, no voting).

## Install

Download a prebuilt binary for your platform from the releases page, then:

```bash
chmod +x plenarai-*        # macOS/Linux only
./plenarai register
./plenarai login
./plenarai setup           # installs the pinned llama.cpp engine + a starter model
./plenarai node --stake 5  # go online and start earning
```

`setup` downloads a pinned `llama-server` build (verified against hard-coded SHA-256 digests) and a starter GGUF model into `~/.plenarai/`.

### Build from source

Requires Go 1.23+.

```bash
go build -o plenarai ./cmd/plenarai
```

Production-style builds with obfuscation: `make release-all`.

## Bringing your own model

Any GGUF file works:

```bash
./plenarai node --model-path /path/to/your-finetune.gguf
```

The bundled engine applies the chat template embedded in the model file. Legacy Ollama users can opt out of the bundled engine with `plenarai setup --engine ollama`.

## Common commands

```bash
./plenarai ask "What is the capital of France?"
./plenarai ask --node-id NODE_UUID "Ask this node directly"
./plenarai scorer-register   # become a judge (eligibility rules apply)
./plenarai status            # balance, ELO, stake, earnings
./plenarai update
```

## Security notes

- Questions travel encrypted; responder nodes must decrypt them to answer but never learn who asked.
- Never include personal data or secrets in a question.
- The engine binds to localhost only; question content never leaves your machine unencrypted.
- Release binaries are obfuscated and their SHA-256 checksums are published. Verify downloads before running them.

## License

MIT — see [LICENSE](LICENSE).
