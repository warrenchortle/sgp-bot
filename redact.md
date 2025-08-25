# Plan: REDACT_WORDS (CSV) auto-redaction

## Goal
- Add optional `REDACT_WORDS` env var as a comma-separated list of strings.
- Remove all occurrences (substring matches), case-insensitive, from any text we post to Bluesky and include in the Signal preview description.

## Steps
- Parse env
  - Read `os.getenv('REDACT_WORDS', '')`.
  - Split by comma, strip whitespace for each, drop empties. No JSON parsing.
  - Configure values only in `.env` (no repository docs/examples).

- Build redactor
  - If list is empty, use identity (no-op) function.
  - Else compile regex: `re.compile('|'.join(re.escape(w) for w in words), re.IGNORECASE)`.
  - Redact via `pattern.sub('', text)`.

- Apply
  - After computing `final_post_text`, run redaction and use the result for:
    - `post_text` in `post_to_bluesky`.
    - `preview_description` in Signal confirmation.
  - Image-only posts: no-op.

- Logging
  - If redaction changed the text, log a brief INFO note (do not print content).

## Notes
- Substring removal is intentional; switch to word boundaries later if needed.
