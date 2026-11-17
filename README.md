# Claude usage tracker

A small self-hosted collector for Claude Code's built-in OpenTelemetry usage reports.
One Python file, standard library only (Python 3.9+, SQLite with JSON support).
It stores token counts, estimated cost, models, sessions and active time per person,
and shows a leaderboard plus a per-person page. Prompts and code are not collected.

## Run

```sh
python3 server.py --check                       # self-test
python3 -m unittest discover -p 'test_telemetry.py' -v
VIEW_KEY='choose-a-password' python3 server.py  # http://127.0.0.1:4318
```

Put HTTPS (Caddy, nginx, a Cloudflare proxy) in front for anything public.

## Add a person

```sh
python3 server.py --add NAME https://your.domain
```

This appends `NAME <token>` to `tokens.txt` (no restart needed) and prints the settings
block for that person to merge into `~/.claude/settings.json`. They must fully restart
Claude Code. To revoke, delete their line. A token can only upload that person's own
usage; it cannot read the dashboard.

## More

- [TELEMETRY_SETUP.md](TELEMETRY_SETUP.md): dashboard, extra metadata, counting and retention.
- [FULL_CONTENT_CAPTURE.md](FULL_CONTENT_CAPTURE.md): optional content capture (read the warnings first).

## Never commit

`tokens.txt`, `.viewkey*`, `*-settings.json` and `usage.db*` hold secrets and usage data;
`.gitignore` excludes them.

## Licence

MIT, see [LICENSE](LICENSE). Bundled fonts (Archivo, Big Shoulders) are under the
SIL Open Font License 1.1 (https://openfontlicense.org); their copyright belongs to their authors.
