# Connect an AI model

Start SILC and try **Offline briefing** first. Its explanations are rule templates, so you can verify the complete workflow without downloading a model or obtaining a key.

## Local Ollama

1. Install and open [Ollama](https://ollama.com).
2. Leave the Terminal running SILC open.
3. Open a second Terminal window and run:

```bash
ollama pull gemma3:4b
```

4. Wait for the download to finish.
5. In SILC, open a finding and choose **Explain with a model**.
6. Select **Ollama (local)**, keep that one finding selected, and generate a briefing.
7. Read its **Reasoning** tab and click an evidence ID.

Ollama must be running. The default model uses local memory and compute. A download or request can take time. If the response fails validation, try a single finding or a different compatible text model.

Optional backend settings:

```dotenv
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gemma3:4b
```

Use the project's configuration template only if you want to change these defaults. In a Terminal opened in the project folder:

```bash
cp -n .env.example .env
```

The `-n` prevents overwriting an existing configuration. Edit `.env` in VS Code, then restart SILC. The adapter accepts only local HTTP Ollama hosts; it rejects a remote host.

[Ollama chat API](https://docs.ollama.com/api/chat) · [Gemma 3 model information](https://ollama.com/library/gemma3)

## Cloud API

1. Obtain an API key in your chosen provider account.
2. Copy the template as above if needed.
3. Set `ALLOW_CLOUD_AI=true`.
4. Set that provider's key and a current text-generation model ID available to your account.
5. Restart SILC.
6. Choose the provider in AI briefing and confirm sharing the selected evidence for that request.

| Provider | Key setting | Model setting | Endpoint family |
| --- | --- | --- | --- |
| Gemini | GEMINI_API_KEY | GEMINI_MODEL | generateContent |
| DeepSeek | DEEPSEEK_API_KEY | DEEPSEEK_MODEL | Chat completions |
| OpenAI | OPENAI_API_KEY | OPENAI_MODEL | Responses |
| Claude | ANTHROPIC_API_KEY | ANTHROPIC_MODEL | Messages |

Example structure; replace the placeholders locally:

```dotenv
ALLOW_CLOUD_AI=true
GEMINI_API_KEY=your-private-key
GEMINI_MODEL=your-available-text-model-id
```

Cloud model IDs are deliberately configurable. A selectable provider means configuration is present; it does not mean a live request has succeeded.

API access, quotas, billing and data-use terms depend on your provider account. This project supplies no keys or credits. A chat subscription and an API account can have separate billing.

Official endpoint references: [Gemini](https://ai.google.dev/api/generate-content), [DeepSeek](https://api-docs.deepseek.com/api/create-chat-completion/), [OpenAI](https://developers.openai.com/api/docs/guides/text), [Claude](https://platform.claude.com/docs/en/api/messages/create).

## What the model receives

At most ten selected findings, including:

- Alert ID, type, severity, matching count and timestamps.
- Source/destination addresses, evidence summary and investigation guidance.
- Rule explanation, missing telemetry, dataset comparison and ATT&CK reference.
- Observed and hypothetical playbook context.
- Up to ten valid matching event IDs per finding.

The adapter does not send the full CSV, complete raw record previews or your analyst notes. Summary fields can still contain IPs, usernames or domains from the selected evidence.

## Why the Reasoning tab always has an explanation

The model must return one structured JSON explanation for **every selected finding**. Each requires:

- An assessment and nonempty rationale.
- Valid evidence IDs from that finding.
- Possible alternatives and missing evidence.
- Suggested checks with a reason for each.
- An unconfirmed next-stage hypothesis and a confidence label.

The backend rejects missing explanations, missing rationales, duplicate/foreign alert IDs, invented event references, extra fields and invalid confidence values. It displays a useful error while preserving the deterministic rule reasoning.

This is structural validation. It does not prove the interpretation is correct, and a valid citation does not prove the associated claim. Review the matching records and the stated limitations.

All model text is escaped before display. The model has no tools to execute commands, change rules or save an analyst decision.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| Provider is disabled | Add its key/model and server cloud opt-in, then restart |
| Ollama connection fails | Open Ollama; confirm the model download finished |
| Model is unavailable | Check the exact model ID and access in your provider account |
| Explanation is incomplete | Select one finding; try again or use another model |
| A request is slow | Wait for it to finish; only one briefing runs at a time |
| Cloud confirmation is required | Read the disclosure and confirm for the selected provider |
| You need a dependable demo now | Choose Offline briefing and explain that it is a template |

Provider errors do not expose raw exception messages, secret-bearing URLs or response bodies. A failed model request leaves rule results available.

## Connection record

The delivery tests use mocked provider responses. Record a real connection only after running it:

| Date | Provider/model | Finding | Explanation and citations reviewed | Result |
| --- | --- | --- | --- | --- |
| | | | | |
