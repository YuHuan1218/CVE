# SigNoz ClickHouse SQL Injection via UpdateLogField/UpdateTraceField field.Name Concatenation

## Summary
SigNoz v0.132.0 is vulnerable to SQL injection within its ClickHouse integration. Authenticated users with the Editor role can execute arbitrary ClickHouse DDL statements by injecting SQL payloads via the `name` field in the `/api/v1/logs/fields` and `/api/v2/traces/fields` endpoints.

## Details
The vulnerability originates from the improper construction of `ALTER TABLE` SQL statements using unescaped user input concatenated via `fmt.Sprintf`.

**Source-to-Sink Link:**
1. **Source:** `POST /api/v1/logs/fields` request JSON `name` field is parsed into `UpdateField.Name` at `pkg/query-service/app/http_handler.go:3240`.
2. **Validation Bypass:** The parsed struct is validated by `ValidateUpdateFieldPayload` at `pkg/query-service/app/logs/validator.go:12`, which only checks if the name is non-empty and matches a specific type regex, but completely fails to escape or reject SQL special characters (like single quotes).
3. **Sink Preparation:** The unescaped `field.Name` is passed to `ClickHouseReader.UpdateLogField` at `pkg/query-service/app/clickhouseReader/reader.go:2710`, where it is directly concatenated into an `ALTER TABLE` DDL query string using `fmt.Sprintf`.
4. **Sink Execution:** The maliciously crafted SQL query is sent to the ClickHouse database via `r.db.Exec(ctx, query)` at `pkg/query-service/app/clickhouseReader/reader.go:2717`.

**Vulnerable Code Snippet (`pkg/query-service/app/clickhouseReader/reader.go:2692-2760`):**
```go
func (r *ClickHouseReader) UpdateLogField(ctx context.Context, field *model.UpdateField) {
    // ...
    colname := utils.GetClickhouseColumnNameV2(field.Type, field.DataType, field.Name)
    q := "ALTER TABLE %s.%s ON CLUSTER %s ADD COLUMN IF NOT EXISTS %s %s DEFAULT %s['%s'] CODEC(ZSTD(1))"
    // Unescaped field.Name is directly concatenated here:
    query := fmt.Sprintf(q, r.logsDB, table, r.cluster, colname, chDataType, attrColName, field.Name)
    err := r.db.Exec(ctx, query)
}
```
*(Note: `UpdateTraceField` at `reader.go:2821-2916` suffers from the exact same vulnerability pattern).*

## POC
**Preconditions:**
- Valid JWT token authenticated with SigNoz Editor role.
- The ClickHouse user configured for SigNoz must have `ALTER` permissions.

**Steps:**
1. Authenticate as an Editor user to obtain a JWT access token.
2. Submit a crafted `POST` request to `/api/v1/logs/fields` with single quotes in the `name` field to break out of the ClickHouse string context and append malicious DDL.

```http
POST /api/v1/logs/fields
Authorization: Bearer <EDITOR_JWT_TOKEN>
Content-Type: application/json

{
    "name": "x'] CODEC(ZSTD(1)), ADD COLUMN injected String DEFAULT 'pwned",
    "dataType": "string",
    "type": "tag",
    "selected": true
}
```
3. Execute a query to verify the `injected` column was successfully added to the table.

## Impact
Authenticated attackers with Editor privileges can abuse this SQL injection to perform DDL injection against the underlying ClickHouse database. This can result in unauthorized modification of the database structure, destruction of data schemas, or under specific database permission configurations, creation of new database users and complete privilege escalation.

## Remediation
1. **Strict Input Validation:** Apply a strict character whitelist for `field.Name` allowing only alphanumeric characters and underscores.
2. **Parameterization/Identifier Escaping:** Refrain from using `fmt.Sprintf` for SQL statement construction. Use parameterized queries if supported by the driver, or correctly escape single quotes and backticks for ClickHouse string and identifier contexts.
3. **Apply Defense-in-Depth:** Ensure the ClickHouse database user used by the query-service has the principle of least privilege applied, restricting destructive DDL actions where possible.

## Disclosure Notes
This vulnerability has been verified against SigNoz version v0.132.0 on the `main` branch.

## Supplemental Information
### Affected products
SigNoz v0.132.0
### Severity
- Scoring method: CVSS v3.1
- Score: 8.8
- Vector string: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
### Weaknesses
- CWE: CWE-89
