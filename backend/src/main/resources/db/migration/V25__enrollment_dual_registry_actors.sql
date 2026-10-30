-- SOV-023: enrollment actor columns reference either credential
-- registry. Human reviewers act through BFF sessions whose
-- identities live in human_membership, not service_account, so the
-- service_account-only foreign keys below made every human case
-- write fail. The columns stay UUID and stay always-set; the
-- maker/checker rule compares ids only and is unchanged. Trust and
-- consent already store actors as registry-agnostic TEXT for the
-- same reason.
ALTER TABLE enrollment DROP CONSTRAINT IF EXISTS enrollment_created_by_account_fkey;
ALTER TABLE enrollment DROP CONSTRAINT IF EXISTS enrollment_decided_by_account_fkey;
ALTER TABLE enrollment_review DROP CONSTRAINT IF EXISTS enrollment_review_reviewer_account_fkey;

COMMENT ON COLUMN enrollment.created_by_account IS
  'Maker id: service_account or human_membership row, tenant-scoped by RLS.';
COMMENT ON COLUMN enrollment.decided_by_account IS
  'Checker id: service_account or human_membership row, tenant-scoped by RLS.';
COMMENT ON COLUMN enrollment_review.reviewer_account IS
  'Reviewer id: service_account or human_membership row, tenant-scoped by RLS.';
