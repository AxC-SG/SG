-- migration-guard: platform-only
-- Rollout must retain the exact assessment request while its worker is pending.
ALTER TABLE platform.ai_grid_policy_rollout_tasks
 DROP CONSTRAINT ai_grid_policy_rollout_tasks_status_check;
ALTER TABLE platform.ai_grid_policy_rollout_tasks
 ADD CONSTRAINT ai_grid_policy_rollout_tasks_status_check CHECK (status IN
  ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','WAITING_FOR_ASSESSMENT','COMPLETED','FAILED','CANCELLED'));

-- Older PROCESSING rows predate leased claims. Preserve a live leased owner;
-- give only unowned legacy rows a grace period before normal expiry recovery.
UPDATE platform.ai_grid_policy_rollout_tasks
 SET lease_expires_at=now()+interval '2 minutes'
 WHERE status='PROCESSING' AND lease_expires_at IS NULL;
