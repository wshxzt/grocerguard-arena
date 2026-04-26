CREATE TABLE defense_log (
  id           STRING(36)   NOT NULL,
  attack_id    STRING(36),
  target_url   STRING(500),
  fixed        BOOL         NOT NULL,
  evidence     STRING(MAX),
  attempted_at TIMESTAMP,
) PRIMARY KEY (id);
