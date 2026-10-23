# Persistent desktop helper protocol

Start `beagle helper-stdio` with private stdin/stdout pipes. Database paths,
queries, and parameters travel only in the protocol. Existing CLI commands and
`serve-stdio` retain their behavior. This mode is part of the optional `cli`
feature; `default-features = false` library consumers are unaffected.

The helper writes one UTF-8 JSON object per line and flushes every message.
Stdout contains protocol messages only. Stderr may contain a generic transport
or protocol failure diagnostic, without request contents. The host must apply
its own deadlines and kill/restart a helper that hangs or fails framing.

## Startup and framing

The first message is:

```json
{"type":"ready","protocol":1,"name":"beagle","version":"0.1.0","operations":["open","stats","query","savedQuery","catalog","savedQueryInfo","entity","ingest","analyze","tag","compose","export","paths","shutdown","importSnapshot","exportToFile","backup","cleanup","getAssetGroups","previewAssetGroups","applyAssetGroups","relayTargets","closeDatabase","setImportHistoryRetention"],"limits":{"requestBytes":1048576,"responseBytes":33554432}}
```

`version` comes from the built crate version. Both limits include the trailing
newline. The helper bounds an incoming line before copying it into its frame
buffer, and serializes responses into a bounded buffer before writing any bytes.
The host must reject an unsupported protocol or missing required operations.

Requests have exactly two fields:

```json
{"id":1,"command":{"type":"open","database":"/absolute/path/graph.db","queryTimeoutMs":30000}}
{"id":2,"command":{"type":"query","cypher":"RETURN $value AS value","parameters":{"value":42}}}
```

IDs are strictly increasing positive integers through `9007199254740991`.
Requests execute serially. The client correlates responses by `id`:

```json
{"type":"response","id":1,"ok":true,"value":null}
{"type":"response","id":2,"ok":true,"value":{"columns":["value"],"rows":[{"value":42}]}}
```

All fields shown for a command are required unless marked optional; unknown
fields are rejected.

| Command type | Fields after `type` | Result |
| --- | --- | --- |
| `open` | `database`, `queryTimeoutMs` | `null`; owns one database connection |
| `closeDatabase` | none | `null`; releases the database so another can be opened |
| `stats` | none | Existing CLI statistics object |
| `query` | `cypher`, `parameters` | Existing columns/rows envelope |
| `savedQuery` | `id`, `parameters` | Existing columns/rows envelope |
| `catalog` | none | Array of authoritative saved-query metadata, including `parameterized_query` and `parameters` |
| `savedQueryInfo` | `id` | One authoritative saved-query metadata object |
| `entity` | `objectid` | Existing columns/rows envelope |
| `ingest` | `paths`, `analyze`; optional `mode`, `historyLimit`, `compactReports` | Existing import report; `mode` defaults to `merge` and also accepts `replace` |
| `analyze` | optional `compactReports` | Existing analysis report using persisted/default options |
| `importSnapshot` | `path`, `analyze`; optional `compactReports` | Import canonical graph JSON from an authorized file |
| `exportToFile` | `path`; optional `kind` (`current` or `raw`) | Write graph JSON atomically to a new file |
| `backup` | `path` | Write a database backup to a new file |
| `cleanup` | `kinds` | Remove selected session/local-group relationships |
| `getAssetGroups` | none | Persisted asset-group configuration |
| `previewAssetGroups` | `configuration` | Preview a rule selection without changing the graph |
| `applyAssetGroups` | `configuration` | Apply rules and return selection/analysis diagnostics |
| `relayTargets` | `source`, `target`, `kind` | Intermediate NTLM relay targets |
| `setImportHistoryRetention` | `limit` (10, 25, 50, or 100) | Update and prune persisted import history |
| `tag` | `objectid`, `tag`, `enabled` | Existing tag report |
| `compose` | `source`, `target`, `kind` | Existing canonical graph snapshot |
| `export` | none | Current canonical graph snapshot |
| `paths` | `source`, `target`, `all`, `maxHops` | Existing columns/rows envelope |
| `shutdown` | none | `null`, followed by clean process exit |

`catalog`, `savedQueryInfo`, `closeDatabase`, and `shutdown` work before `open`.
All other operations require a successful `open`. A helper can open only one
database at a time; close it before switching projects. An unsuccessful open may be retried.
EOF after a complete line cleanly releases the database without an extra reply.
An incomplete final line is a protocol error.

`compactReports` defaults to false. When true, large import/analysis diagnostic
collections are bounded and include explicit omitted counts. File export and
backup avoid transporting large graphs through the bounded response channel;
hosts must authorize the destination path before sending either operation.

## Input bounds

- Database: absolute path or `:memory:`. Import paths: 1–100 absolute paths.
  Paths are limited to 4,096 UTF-16 code units and reject control characters.
- Query timeout: integer milliseconds from 1 through 120,000.
- Cypher: nonempty, at most 65,536 UTF-16 code units. Tab, CR, and LF are allowed;
  other ASCII control characters are rejected.
- Saved IDs, entity IDs, and endpoints: nonempty, at most 512 UTF-16 code units.
  Relationship kind: at most 128. These fields reject ASCII control characters.
- Parameters: JSON object, serialized UTF-8 size at most 65,536 bytes, depth at
  most 32, and at most 100,000 values including the root object.
- `maxHops`: integer 1–64. `analyze`, `all`, and `enabled`: JSON booleans.
  `tag`: exactly `owned` or `admin_tier_0`.

## Errors and trust

Operation errors return a response and the session stays usable:

```json
{"type":"response","id":3,"ok":false,"error":{"code":"database_not_open","message":"Open a database before this operation."}}
```

Codes include `invalid_input`, `database_not_open`, `database_already_open`,
`operation_failed`, and `response_too_large`. Native errors are intentionally
replaced with fixed messages rather than returning query text, paths, or other
request contents. An oversized response yields `response_too_large`; no partial
success frame is emitted. A failed response does not undo a completed mutation.

Malformed JSON, unknown fields/commands, invalid IDs, oversized input, truncated
input, and input failures emit one sanitized fatal message and exit nonzero:

```json
{"type":"fatal","error":{"code":"invalid_request","message":"Invalid helper request envelope."}}
```

Other fatal codes are `invalid_request_id`, `request_too_large`,
`truncated_request`, and `input_error`. A broken stdout pipe can prevent delivery
of a final message. Treat EOF without a normal shutdown/closed input as failure.

The helper has the privileges of its launching user. It is not an OS sandbox.
The trusted host owns executable verification, file-picker authorization,
renderer isolation, graph-only query restrictions, and process deadlines. The
helper exposes the library's read-only Cypher behavior; hosts that must forbid
file-reading or dynamic-query capabilities must enforce that additional policy
before sending commands. Paths are data and no command is executed via a shell.
