-- Enable REPLICA IDENTITY FULL for complete row data in realtime updates
ALTER TABLE public.honeypot_logs REPLICA IDENTITY FULL;