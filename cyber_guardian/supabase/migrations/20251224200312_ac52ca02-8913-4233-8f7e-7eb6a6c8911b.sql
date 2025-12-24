-- Create chat_messages table for secure chat
CREATE TABLE public.chat_messages (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  sender_name TEXT NOT NULL,
  content TEXT NOT NULL,
  is_ai BOOLEAN NOT NULL DEFAULT false,
  auto_delete BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

-- Allow public access for demo
CREATE POLICY "Allow public read chat_messages"
  ON public.chat_messages
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert chat_messages"
  ON public.chat_messages
  FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Allow public delete chat_messages"
  ON public.chat_messages
  FOR DELETE
  USING (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.chat_messages;

-- Create honeypot_logs table
CREATE TABLE public.honeypot_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  event_type TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  username TEXT,
  location TEXT,
  user_agent TEXT,
  severity TEXT NOT NULL DEFAULT 'warning',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.honeypot_logs ENABLE ROW LEVEL SECURITY;

-- Allow public access
CREATE POLICY "Allow public read honeypot_logs"
  ON public.honeypot_logs
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert honeypot_logs"
  ON public.honeypot_logs
  FOR INSERT
  WITH CHECK (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.honeypot_logs;