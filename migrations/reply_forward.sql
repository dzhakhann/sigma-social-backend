-- Reply-to preview (Telegram-style quoting) and forwarded-message label.
-- Both are self-contained snapshots taken at send time (sender name, quoted
-- text/thumbnail) so they still render correctly even after the quoted
-- message is gone from the device-stored chat history.
alter table messages add column if not exists reply_to jsonb;
alter table messages add column if not exists forwarded_from text;
