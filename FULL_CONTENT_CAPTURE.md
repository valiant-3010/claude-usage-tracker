# Full conversation capture — deferred

Status: explicitly deferred at the owner's request. This update does not enable
prompt, response, tool-content, or raw API-body capture in any client settings.
The collector supports inspecting those fields if they are enabled later.

## What this would add

- User prompt text and assistant response text.
- Tool input arguments, commands, tool outputs, and richer skill/plugin/MCP names.
- Raw Messages API request and response bodies, including conversation history.
- Correlation through session, request, trace, and span IDs where the exporter supplies them.

## Work needed before enabling

1. Deploy `server.py` and `telemetry.py` together. Route authenticated POST requests
   for `/v1/metrics`, `/v1/logs`, and `/v1/traces` through the existing HTTPS proxy.
2. Enable metadata events and tracing using the settings in `TELEMETRY_SETUP.md`.
   Verify new records arrive in the dashboard's Collection & setup tab.
3. Decide whose content should be collected. Enable content only for those users;
   the dashboard password grants access to all stored members' records.
4. Plan disk capacity, backup retention, and deletion. Raw bodies may repeat entire
   conversation histories; the current default 200 MB database limit can fill quickly.
   Increase `MAX_DB_MB` deliberately. Automatic retention/deletion is not implemented.
5. Merge the following flags into the selected user's existing `~/.claude/settings.json`
   `env` object. Preserve their existing endpoint and private upload token.

```json
{
  "OTEL_LOG_USER_PROMPTS": "1",
  "OTEL_LOG_ASSISTANT_RESPONSES": "1",
  "OTEL_LOG_TOOL_DETAILS": "1",
  "OTEL_LOG_TOOL_CONTENT": "1",
  "OTEL_LOG_RAW_API_BODIES": "1"
}
```

6. Restart Claude Code. Run a non-sensitive test conversation. Verify its log events,
   trace spans, and complete raw records in `/explore` before relying on the capture.
7. Verify the installed Claude Code version supports the requested flags. Some
   attributes depend on app version, model, provider, and whether the session is
   local, desktop, or cloud-hosted.

## Limits

- This may collect secrets or private source code included in conversations or tool output.
- Exporter-side truncation still applies. `CLAUDE_CODE_OTEL_CONTENT_MAX_LENGTH`
  controls content size in supported versions; the collector accepts at most 4 MB
  per POST (including decompressed size).
- File-mode raw bodies (`file:<dir>`) produce local paths, not uploaded file contents.
  A file ingestion mechanism would be needed to display those referenced files.
- Previously discarded prompts, attributes, and payloads cannot be reconstructed.
- Claude Design web/app and ordinary Claude chat are not connected by these flags.
  A supported separate source would be needed for their usage data.
- Disabling future capture does not delete data already stored or backed up.

Reference: https://code.claude.com/docs/en/monitoring-usage
