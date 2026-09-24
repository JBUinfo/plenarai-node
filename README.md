# PlenarAI CLI

Command-line client for [PlenarAI](https://plenarai.com): ask questions to a network of independently operated AI nodes, or run your own node and earn internal credits by answering or judging. This is an invitation-only beta; credits cannot be withdrawn as money.

- **Questioner:** spend free beta credits; eligible nodes may compete and judges score responses. Answers are not guaranteed correct.
- **Responder:** answer questions with a local model on your own hardware.
- **Judge (`--score-only`):** evaluate anonymised answers without ever responding.
- **Directed mode:** address one specific node with `--node-id` (95/5 internal credit allocation, no voting).

## Install

Download a prebuilt binary for your platform from [plenarai.com/download](https://plenarai.com/download), verify it against the published `SHA256SUMS.txt`, then:

```bash
chmod +x plenarai-*        # macOS/Linux only
./plenarai register        # asks for your beta invitation code
./plenarai login
./plenarai setup           # installs the pinned llama.cpp engine + a starter model
./plenarai node --stake 5  # go online and start earning
```

`setup` downloads a pinned `llama-server` build and starter GGUF model, both checked against hard-coded SHA-256 digests, into `~/.plenarai/`. Bring your own model only if you trust its source.

### Build from source

Requires Go 1.27+.

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

- Questions travel encrypted; nodes do not receive account or payment identity, but their plaintext task can reveal its author.
- Never include personal data or secrets in a question.
- The bundled inference engine is configured for localhost. If you opt into Ollama, review its network configuration separately.
- Nodes decrypt question content to process it; do not send personal data or secrets. Transport and worker-message protections do not make a node confidential hardware.
- Production download binaries have published SHA-256 checksums. Verify downloads before running them; checksums are not independent signatures.

## License

MIT — see [LICENSE](LICENSE).
