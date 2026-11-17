# Telemetry explorer

Notes on running the telemetry explorer locally. A remote deployment and any active
Claude Code user settings are not affected by following these steps.

## Start and test

Keep `server.py` and `telemetry.py` in the same folder. Python 3.9+ and its standard
library are sufficient. SQLite must include JSON support.

```sh
python3 server.py --check
python3 -m unittest discover -p 'test_telemetry.py' -v
VIEW_KEY='<existing dashboard password>' python3 server.py
```

The server listens on `127.0.0.1:4318`. Keep HTTPS/reverse-proxy configuration for
remote deployments. The existing member tokens remain valid for all three ingest
routes. Upload tokens cannot view or export the dashboard.

Before the first run, back up `usage.db`. Startup adds new tables/indexes without
changing the existing points table. Legacy rows are copied into the explorer with
an explicit legacy marker. No missing historic attributes are fabricated, and
historical totals are not retrospectively corrected. Receipt time is unknown for
legacy rows. New received records have both event and receipt timestamps.

## Dashboard

Use **Explore all telemetry** from the leaderboard or member page.

- **Overview:** all metric names/types, gauges, events/errors, event durations,
  trace durations, daily trends, IST hourly heatmap, member shares, cache reuse.
- **Projects & sessions:** group by any received attribute, including repository,
  session, model, main/subagent/auxiliary work, agent, skill, plugin, MCP server,
  app entrypoint, effort, speed, or trace ID. Click a value to inspect its records.
- **All records:** time-ordered metric, event, and trace records with complete raw
  resource/scope/payload details. No metric-name allowlist is applied.
- **Field catalog:** every observed attribute key and signal name. Use these exact
  keys when an installed exporter names a dimension differently.
- **Collection & setup:** received signals, data-quality labels, metadata settings,
  and clearly marked unavailable sources.

Filters support member, signal, metric/event name, UTC date interval, an arbitrary
attribute key/value, and raw-text search. Empty/missing fields mean not received.

**Download all matching records** streams NDJSON without a row limit. JSON and CSV
page downloads contain up to 100 records; JSON includes a `next` URL and CSV uses
an HTTP `Link: rel=next` header. CSV escapes spreadsheet-formula prefixes.

## Enable additional metadata on a client later

Deploy the new collector first. Then merge this into the user's existing `env`
object, preserving `OTEL_EXPORTER_OTLP_ENDPOINT`, protocol, and upload-token headers:

```json
{
  "OTEL_LOGS_EXPORTER": "otlp",
  "OTEL_TRACES_EXPORTER": "otlp",
  "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA": "1",
  "OTEL_METRICS_INCLUDE_SESSION_ID": "true",
  "OTEL_METRICS_INCLUDE_VERSION": "true",
  "OTEL_METRICS_INCLUDE_ENTRYPOINT": "true",
  "OTEL_METRICS_INCLUDE_REPOSITORY": "true",
  "OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE": "delta"
}
```

Restart Claude Code. `/v1/logs` and `/v1/traces` must be routed to the server as well
as `/v1/metrics`. Tracing is a beta Claude Code feature. Optional content capture
has its own deferred checklist in `FULL_CONTENT_CAPTURE.md`.

`--add` generates new-member settings with metadata exporters enabled. Existing
client files are left unchanged in this local-only update.

## Counting and retention

- Original JSON fields are retained per metric point, log record, and span.
  Special non-finite numbers are represented as strings in stored JSON.
- Exact record replays are ignored within each member/signal.
- Cumulative sums are reconciled in timestamp order per series/start time, including
  out-of-order arrivals. Counter resets start a new increment sequence.
- Gauges, histograms, and summaries remain inspectable and are not added to token totals.
- Logs/traces are not added to token totals because they can describe the same usage
  as metrics. Unsupported or invalid numeric values remain inspectable in raw data.
- Sums with unspecified temporality are treated as increments and labeled accordingly.
- Legacy data retains the old counting behavior. Session/resource IDs must be present
  to distinguish independent cumulative series reliably.
- Cumulative increments are attributed to the sample timestamp. Missing exports can
  move an increment into a later time bucket; this is not a per-request reconstruction.
- The database limit defaults to 200 MB (`MAX_DB_MB`); uploads return 507 after the
  limit is exceeded. This is not a strict disk quota or retention system. Back up
  and size storage before enabling high-volume traces or content capture.
- Raw record storage is plaintext SQLite protected by local file permissions and
  dashboard authentication. No additional encryption or per-member read isolation
  was introduced.

Claude Design, ordinary Claude chat, remaining subscription allowance, and reset
times require another supported data source; this collector cannot infer them.

Reference: https://code.claude.com/docs/en/monitoring-usage
