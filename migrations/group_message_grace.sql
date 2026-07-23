-- A fully-acked group message is no longer relayed to anyone (pending_acks
-- becomes []), but the row is kept a while longer so reactions/seen-by still
-- have something to attach to instead of the row vanishing instantly the
-- moment the last member acks (common within seconds in small groups).
-- sweepFullyAckedGroupMessages() in server.js reaps rows past the grace
-- window (48h).
alter table group_messages add column if not exists fully_acked_at timestamptz;
