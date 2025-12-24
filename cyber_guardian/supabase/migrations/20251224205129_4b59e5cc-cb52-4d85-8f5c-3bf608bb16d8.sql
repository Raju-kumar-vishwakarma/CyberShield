-- Create user activity logs table
CREATE TABLE public.user_activity_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id),
  action_type TEXT NOT NULL,
  description TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.user_activity_logs ENABLE ROW LEVEL SECURITY;

-- Users can view their own activity
CREATE POLICY "Users can view their own activity logs"
ON public.user_activity_logs
FOR SELECT
USING (auth.uid() = user_id);

-- Users can insert their own activity
CREATE POLICY "Users can insert their own activity logs"
ON public.user_activity_logs
FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Allow anonymous inserts for system tracking (honeypot, etc)
CREATE POLICY "Allow anonymous activity logging"
ON public.user_activity_logs
FOR INSERT
WITH CHECK (user_id IS NULL);

-- Allow reading anonymous logs
CREATE POLICY "Allow reading anonymous logs"
ON public.user_activity_logs
FOR SELECT
USING (user_id IS NULL);

-- Create email breach checks table
CREATE TABLE public.email_breach_checks (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT NOT NULL,
  is_breached BOOLEAN DEFAULT false,
  breach_count INTEGER DEFAULT 0,
  breach_sources TEXT[],
  last_checked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  ai_analysis TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.email_breach_checks ENABLE ROW LEVEL SECURITY;

-- Anyone can check and view breaches (public security tool)
CREATE POLICY "Anyone can insert breach checks"
ON public.email_breach_checks
FOR INSERT
WITH CHECK (true);

CREATE POLICY "Anyone can view breach checks"
ON public.email_breach_checks
FOR SELECT
USING (true);

-- Create ssl checks table
CREATE TABLE public.ssl_checks (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  domain TEXT NOT NULL,
  is_valid BOOLEAN DEFAULT false,
  issuer TEXT,
  expires_at TIMESTAMP WITH TIME ZONE,
  grade TEXT,
  vulnerabilities TEXT[],
  checked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.ssl_checks ENABLE ROW LEVEL SECURITY;

-- Anyone can check and view SSL results (public security tool)
CREATE POLICY "Anyone can insert ssl checks"
ON public.ssl_checks
FOR INSERT
WITH CHECK (true);

CREATE POLICY "Anyone can view ssl checks"
ON public.ssl_checks
FOR SELECT
USING (true);

-- Enable realtime for activity logs
ALTER PUBLICATION supabase_realtime ADD TABLE public.user_activity_logs;