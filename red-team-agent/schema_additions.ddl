CREATE TABLE cwe_registry (
  cwe_id      STRING(20)   NOT NULL,
  name        STRING(200)  NOT NULL,
  rank        INT64        NOT NULL,
  score       FLOAT64      NOT NULL,
  rank_delta  INT64,
  applicable  BOOL,
  last_synced TIMESTAMP,
) PRIMARY KEY (cwe_id);

CREATE TABLE attack_log (
  id           STRING(36)   NOT NULL,
  cwe_id       STRING(20)   NOT NULL,
  target_url   STRING(500),
  payload      STRING(MAX),
  status       STRING(50),
  evidence     STRING(MAX),
  attempted_at TIMESTAMP,
) PRIMARY KEY (id);
