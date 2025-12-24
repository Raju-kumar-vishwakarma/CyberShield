-- Create network_threats table for storing detected threats
CREATE TABLE public.network_threats (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  source_ip TEXT NOT NULL,
  destination TEXT NOT NULL,
  protocol TEXT NOT NULL,
  bytes_transferred TEXT,
  threat_type TEXT,
  severity TEXT NOT NULL DEFAULT 'low',
  confidence NUMERIC(5,2) DEFAULT 0,
  ai_analysis TEXT,
  status TEXT NOT NULL DEFAULT 'detected',
  detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.network_threats ENABLE ROW LEVEL SECURITY;

-- Allow public read access for demo purposes (no auth required)
CREATE POLICY "Allow public read access"
  ON public.network_threats
  FOR SELECT
  USING (true);

-- Allow public insert for demo (edge function inserts)
CREATE POLICY "Allow public insert"
  ON public.network_threats
  FOR INSERT
  WITH CHECK (true);

-- Allow public update
CREATE POLICY "Allow public update"
  ON public.network_threats
  FOR UPDATE
  USING (true);

-- Enable realtime for network_threats table
ALTER PUBLICATION supabase_realtime ADD TABLE public.network_threats;

-- Create suspicious_ips table
CREATE TABLE public.suspicious_ips (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_address TEXT NOT NULL UNIQUE,
  location TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  severity TEXT NOT NULL DEFAULT 'low',
  is_blocked BOOLEAN NOT NULL DEFAULT false,
  last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.suspicious_ips ENABLE ROW LEVEL SECURITY;

-- Allow public access for demo
CREATE POLICY "Allow public read suspicious_ips"
  ON public.suspicious_ips
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert suspicious_ips"
  ON public.suspicious_ips
  FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Allow public update suspicious_ips"
  ON public.suspicious_ips
  FOR UPDATE
  USING (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.suspicious_ips;