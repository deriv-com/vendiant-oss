-- Migration 001: Rename api_credentials.config to finegrained_scopes
-- Purpose: repurpose the existing JSONB column to store fine-grained scope lists
--          for individual API keys (group_name = 'finegrained').
--          Existing rows keep their data (all currently '{}') and the column
--          default is changed to NULL since an empty object has no meaning here.
--
-- Rollback:
--   ALTER TABLE api_credentials RENAME COLUMN finegrained_scopes TO config;
--   ALTER TABLE api_credentials ALTER COLUMN finegrained_scopes SET DEFAULT '{}'::jsonb;

BEGIN;

ALTER TABLE api_credentials
    RENAME COLUMN config TO finegrained_scopes;

ALTER TABLE api_credentials
    ALTER COLUMN finegrained_scopes SET DEFAULT NULL;

-- Normalise existing empty-object rows to NULL (they carry no scope data)
UPDATE api_credentials
SET finegrained_scopes = NULL
WHERE finegrained_scopes = '{}'::jsonb;

COMMIT;
