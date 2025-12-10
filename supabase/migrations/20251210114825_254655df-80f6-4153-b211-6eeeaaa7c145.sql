-- Learning VAPT Assistant Tables
-- This module is for AUTHORIZED PENETRATION TESTING ONLY. Misuse is prohibited.

-- Test Actions table - logs all VAPT activities
CREATE TABLE public.vapt_test_actions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  injection_point TEXT, -- e.g., query parameter, header, cookie, body field
  payload_sent TEXT,
  transformed_payload TEXT,
  request_headers JSONB DEFAULT '{}',
  request_body TEXT,
  response_status INTEGER,
  response_headers JSONB DEFAULT '{}',
  response_body TEXT,
  outcome_label TEXT DEFAULT 'no_effect', -- no_effect, potential_issue, confirmed_issue
  test_type TEXT NOT NULL, -- XSS, SQLi, SSRF, IDOR, etc.
  notes TEXT,
  operator_id UUID REFERENCES auth.users(id),
  domain TEXT GENERATED ALWAYS AS (
    CASE 
      WHEN target_url ~ '^https?://' THEN split_part(split_part(target_url, '://', 2), '/', 1)
      ELSE split_part(target_url, '/', 1)
    END
  ) STORED,
  embedding_text TEXT GENERATED ALWAYS AS (
    COALESCE(test_type, '') || ' ' || 
    COALESCE(injection_point, '') || ' ' || 
    COALESCE(outcome_label, '') || ' ' || 
    COALESCE(notes, '')
  ) STORED,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Suggestions table - stores AI-generated improvement suggestions
CREATE TABLE public.vapt_suggestions (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  action_id UUID REFERENCES public.vapt_test_actions(id) ON DELETE CASCADE,
  explanation TEXT NOT NULL,
  strategies JSONB NOT NULL DEFAULT '[]', -- array of suggested strategies
  payload_templates JSONB DEFAULT '[]', -- safe templates with placeholders
  model_used TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Feedback table - tracks user feedback on suggestions for learning
CREATE TABLE public.vapt_feedback (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  action_id UUID REFERENCES public.vapt_test_actions(id) ON DELETE CASCADE,
  suggestion_id UUID REFERENCES public.vapt_suggestions(id) ON DELETE CASCADE,
  rating TEXT NOT NULL, -- helpful, not_helpful, partially_helpful
  comments TEXT,
  operator_id UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Configuration table for assistant settings
CREATE TABLE public.vapt_config (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  operator_id UUID REFERENCES auth.users(id) UNIQUE,
  mode TEXT NOT NULL DEFAULT 'observe_only', -- observe_only, assistive, auto_sandboxed
  allowed_targets TEXT[] DEFAULT '{}', -- whitelist of allowed domains/IPs
  log_level TEXT DEFAULT 'info',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.vapt_test_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vapt_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vapt_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vapt_config ENABLE ROW LEVEL SECURITY;

-- RLS Policies - users can only access their own data
CREATE POLICY "Users can view their own test actions"
ON public.vapt_test_actions FOR SELECT
USING (auth.uid() = operator_id);

CREATE POLICY "Users can create their own test actions"
ON public.vapt_test_actions FOR INSERT
WITH CHECK (auth.uid() = operator_id);

CREATE POLICY "Users can update their own test actions"
ON public.vapt_test_actions FOR UPDATE
USING (auth.uid() = operator_id);

CREATE POLICY "Users can delete their own test actions"
ON public.vapt_test_actions FOR DELETE
USING (auth.uid() = operator_id);

CREATE POLICY "Users can view suggestions for their actions"
ON public.vapt_suggestions FOR SELECT
USING (EXISTS (
  SELECT 1 FROM public.vapt_test_actions 
  WHERE id = action_id AND operator_id = auth.uid()
));

CREATE POLICY "Users can create suggestions"
ON public.vapt_suggestions FOR INSERT
WITH CHECK (EXISTS (
  SELECT 1 FROM public.vapt_test_actions 
  WHERE id = action_id AND operator_id = auth.uid()
));

CREATE POLICY "Users can manage their feedback"
ON public.vapt_feedback FOR ALL
USING (auth.uid() = operator_id);

CREATE POLICY "Users can manage their config"
ON public.vapt_config FOR ALL
USING (auth.uid() = operator_id);

-- Indexes for similarity search
CREATE INDEX idx_vapt_actions_domain ON public.vapt_test_actions(domain);
CREATE INDEX idx_vapt_actions_test_type ON public.vapt_test_actions(test_type);
CREATE INDEX idx_vapt_actions_injection_point ON public.vapt_test_actions(injection_point);
CREATE INDEX idx_vapt_actions_outcome ON public.vapt_test_actions(outcome_label);
CREATE INDEX idx_vapt_actions_operator ON public.vapt_test_actions(operator_id);
CREATE INDEX idx_vapt_actions_embedding_text ON public.vapt_test_actions USING gin(to_tsvector('english', embedding_text));

-- Function to find similar past actions
CREATE OR REPLACE FUNCTION public.find_similar_vapt_actions(
  p_operator_id UUID,
  p_test_type TEXT,
  p_injection_point TEXT DEFAULT NULL,
  p_domain TEXT DEFAULT NULL,
  p_search_text TEXT DEFAULT NULL,
  p_limit INTEGER DEFAULT 5
)
RETURNS TABLE (
  id UUID,
  target_url TEXT,
  method TEXT,
  injection_point TEXT,
  payload_sent TEXT,
  outcome_label TEXT,
  test_type TEXT,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE,
  similarity_score FLOAT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN QUERY
  SELECT 
    a.id,
    a.target_url,
    a.method,
    a.injection_point,
    a.payload_sent,
    a.outcome_label,
    a.test_type,
    a.notes,
    a.created_at,
    (
      CASE WHEN a.test_type = p_test_type THEN 0.4 ELSE 0.0 END +
      CASE WHEN a.injection_point = p_injection_point THEN 0.3 ELSE 0.0 END +
      CASE WHEN a.domain = p_domain THEN 0.2 ELSE 0.0 END +
      CASE WHEN p_search_text IS NOT NULL AND a.embedding_text ILIKE '%' || p_search_text || '%' THEN 0.1 ELSE 0.0 END
    )::FLOAT AS similarity_score
  FROM public.vapt_test_actions a
  WHERE a.operator_id = p_operator_id
    AND a.test_type = p_test_type
    AND (p_injection_point IS NULL OR a.injection_point = p_injection_point)
    AND (p_domain IS NULL OR a.domain = p_domain)
  ORDER BY similarity_score DESC, a.created_at DESC
  LIMIT p_limit;
END;
$$;