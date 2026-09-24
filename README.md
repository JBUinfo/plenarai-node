# PlenarAI CLI

Command-line client for [PlenarAI](https://plenarai.com): ask questions to a network of independently operated AI nodes, or run your own node and earn internal credits by answering or judging. The free beta is open to adults aged 18 or older. There are no payments or cash rewards; credits cannot be withdrawn as money.

- **Questioner:** spend free beta credits; eligible nodes may compete and judges score responses. Answers are not guaranteed correct.
- **Responder:** answer questions with a local model on your own hardware.
- **Judge (`--score-only`):** evaluate anonymised answers without ever responding.
- **Directed mode:** address one specific node with `--node-id` (95/5 internal credit allocation, no voting).

## Install

Download a prebuilt binary for your platform from [plenarai.com/download](https://plenarai.com/download), verify the signed `SHA256SUMS.txt` manifest and compare your binary's hash, then:

```bash
chmod +x plenarai-*        # macOS/Linux only
./plenarai register        # asks you to confirm that you are at least 18
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

Production-style builds for five platforms: `make release-all`. These builds are not obfuscated or signed by the operating-system vendor.

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
- Production download binaries have a SHA-256 manifest signed by the `JBUinfo/plenarai-cli` GitHub Actions workflow using Sigstore. Download `SHA256SUMS.txt.sigstore.json` alongside the manifest and verify its exact workflow identity before comparing your binary's hash. This is a build-origin signature, not Windows Authenticode or macOS Developer ID signing.

For binaries from `plenarai.com/download`, use:

```bash
cosign verify-blob SHA256SUMS.txt --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity https://github.com/JBUinfo/plenarai-cli/.github/workflows/build-deploy.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For GitHub release assets, replace `build-deploy.yml` with `release-public.yml` in the identity above. A valid signature only authenticates the manifest; you must still compare the binary's SHA-256 against the signed entry.

## License

MIT — see [LICENSE](LICENSE).
