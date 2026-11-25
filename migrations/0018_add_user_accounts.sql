-- User-account (MTProto userbot) support: bot rows can now be user accounts.
ALTER TABLE bots ADD COLUMN account_type TEXT NOT NULL DEFAULT 'bot' CHECK (account_type IN ('bot', 'user'));
ALTER TABLE bots ADD COLUMN phone TEXT;
ALTER TABLE bots ADD COLUMN mtproto_session TEXT;
ALTER TABLE bots ADD COLUMN update_state TEXT;
-- Saved tasks can be re-attached to either kind of account.
ALTER TABLE saved_tasks ADD COLUMN account_id TEXT;
