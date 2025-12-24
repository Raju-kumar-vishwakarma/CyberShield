-- Create phishing_scans table for storing scan results
CREATE TABLE public.phishing_scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  content_preview TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  confidence NUMERIC(5,2) DEFAULT 0,
  threat_indicators JSONB DEFAULT '[]'::jsonb,
  ai_analysis TEXT,
  detected_urls TEXT[],
  scanned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.phishing_scans ENABLE ROW LEVEL SECURITY;

-- Allow public access for demo
CREATE POLICY "Allow public read phishing_scans"
  ON public.phishing_scans
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert phishing_scans"
  ON public.phishing_scans
  FOR INSERT
  WITH CHECK (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.phishing_scans;

-- Create threat_analytics table for aggregated stats
CREATE TABLE public.threat_analytics (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  date DATE NOT NULL DEFAULT CURRENT_DATE,
  threat_type TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'low',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(date, threat_type, severity)
);

-- Enable RLS
ALTER TABLE public.threat_analytics ENABLE ROW LEVEL SECURITY;

-- Allow public access for demo
CREATE POLICY "Allow public read threat_analytics"
  ON public.threat_analytics
  FOR SELECT
  USING (true);

CREATE POLICY "Allow public insert threat_analytics"
  ON public.threat_analytics
  FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Allow public update threat_analytics"
  ON public.threat_analytics
  FOR UPDATE
  USING (true);

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.threat_analytics;