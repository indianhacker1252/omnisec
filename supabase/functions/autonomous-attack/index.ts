import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.7.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface AttackStep {
  step: number;
  action: string;
  tool: string;
  parameters: Record<string, any>;
  status: 'pending' | 'running' | 'success' | 'failed';
  result?: any;
  error?: string;
  learnings?: string;
}

interface AttackChain {
  target: string;
  objective: string;
  steps: AttackStep[];
  currentStep: number;
  status: 'planning' | 'executing' | 'learning' | 'completed' | 'failed';
  findings: any[];
  learnings: string[];
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('authorization');
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey, {
      global: { headers: { Authorization: authHeader! } }
    });

    // Verify user is admin
    const { data: { user } } = await supabase.auth.getUser(authHeader!.replace('Bearer ', ''));
    if (!user) throw new Error('Unauthorized');

    const { data: roleData } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .single();

    if (roleData?.role !== 'admin') {
      throw new Error('Admin access required');
    }

    const { target, objective, mode = 'autonomous' } = await req.json();

    console.log(`[Autonomous Attack] Target: ${target}, Objective: ${objective}, Mode: ${mode}`);

    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    if (!LOVABLE_API_KEY) throw new Error('LOVABLE_API_KEY not configured');

    // Step 1: AI generates attack plan
    const attackChain: AttackChain = await generateAttackPlan(target, objective, LOVABLE_API_KEY);
    
    console.log(`[Attack Plan] Generated ${attackChain.steps.length} steps`);

    // Step 2: Execute attack chain autonomously
    if (mode === 'autonomous') {
      await executeAttackChain(attackChain, supabase, authHeader!, LOVABLE_API_KEY);
    }

    // Step 3: Store results and learnings
    await storeAttackResults(attackChain, user.id, supabase);

    return new Response(JSON.stringify({
      success: true,
      attackChain,
      summary: {
        target: attackChain.target,
        stepsExecuted: attackChain.currentStep,
        totalSteps: attackChain.steps.length,
        status: attackChain.status,
        findings: attackChain.findings.length,
        learnings: attackChain.learnings
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[Autonomous Attack Error]:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function generateAttackPlan(target: string, objective: string, apiKey: string): Promise<AttackChain> {
  const systemPrompt = `You are an elite autonomous penetration testing AI with expertise in:
- OWASP Top 10 vulnerabilities
- Network reconnaissance and enumeration
- Web application security testing
- API security assessment
- Authentication and authorization bypass
- SQL injection, XSS, CSRF attacks
- Infrastructure vulnerability analysis

You MUST respond with ONLY a valid JSON object (no markdown, no explanation) defining an attack chain.

Available tools you can use:
1. "recon" - Shodan reconnaissance for target discovery
2. "webapp-scan" - Deep web application scanning (ZAP-style)
3. "vuln-intel" - CVE and vulnerability intelligence
4. "payload-generator" - Generate exploit payloads
5. "wireless-scan" - Wireless network analysis
6. "port-scan" - Network port enumeration
7. "subdomain-enum" - Subdomain discovery
8. "tech-fingerprint" - Technology stack identification

Create a multi-step attack chain that:
1. Starts with reconnaissance
2. Identifies attack surface
3. Scans for vulnerabilities
4. Attempts exploitation (simulated)
5. Reports findings

Respond with JSON in this exact format:
{
  "target": "${target}",
  "objective": "${objective}",
  "steps": [
    {
      "step": 1,
      "action": "Reconnaissance - Discover target infrastructure",
      "tool": "recon",
      "parameters": {"target": "${target}"},
      "status": "pending"
    }
  ],
  "currentStep": 0,
  "status": "planning",
  "findings": [],
  "learnings": []
}`;

  const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `Generate an attack chain for target: ${target} with objective: ${objective}. Remember: respond with ONLY valid JSON, no markdown formatting.` }
      ],
      temperature: 0.7,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('[AI Plan Error]:', response.status, errorText);
    throw new Error(`Failed to generate attack plan: ${response.status}`);
  }

  const data = await response.json();
  let planText = data.choices[0].message.content.trim();
  
  // Remove markdown code blocks if present
  planText = planText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  
  try {
    const attackChain = JSON.parse(planText);
    console.log('[Attack Plan Generated]:', JSON.stringify(attackChain, null, 2));
    return attackChain;
  } catch (parseError) {
    console.error('[JSON Parse Error]:', parseError);
    console.error('[Raw Response]:', planText);
    throw new Error('Failed to parse attack plan from AI');
  }
}

async function executeAttackChain(
  chain: AttackChain, 
  supabase: any, 
  authHeader: string,
  apiKey: string
) {
  chain.status = 'executing';
  
  for (let i = 0; i < chain.steps.length; i++) {
    const step = chain.steps[i];
    chain.currentStep = i + 1;
    step.status = 'running';
    
    console.log(`[Executing Step ${step.step}] ${step.action}`);
    
    try {
      // Execute the tool
      const result = await executeTool(step.tool, step.parameters, supabase, authHeader);
      step.result = result;
      step.status = 'success';
      
      // Analyze results with AI
      const analysis = await analyzeStepResult(step, result, apiKey);
      
      if (analysis.vulnerabilities?.length > 0) {
        chain.findings.push(...analysis.vulnerabilities);
      }
      
      if (analysis.nextStepSuggestion) {
        chain.learnings.push(`Step ${step.step}: ${analysis.nextStepSuggestion}`);
      }
      
      console.log(`[Step ${step.step} Success]`, {
        findings: analysis.vulnerabilities?.length || 0,
        suggestion: analysis.nextStepSuggestion
      });
      
    } catch (error) {
      step.status = 'failed';
      step.error = error instanceof Error ? error.message : 'Unknown error';
      
      console.error(`[Step ${step.step} Failed]:`, error);
      
      // AI learns from failure and adapts
      const learning = await learnFromFailure(step, error, apiKey);
      step.learnings = learning.insights;
      chain.learnings.push(`Step ${step.step} failure: ${learning.insights}`);
      
      // Try to adapt strategy
      if (learning.retryWithDifferentApproach) {
        step.parameters = learning.newParameters;
        console.log(`[Adapting Strategy] Retrying step ${step.step} with new approach`);
        i--; // Retry this step
      }
    }
  }
  
  chain.status = 'completed';
}

async function executeTool(
  tool: string, 
  parameters: Record<string, any>,
  supabase: any,
  authHeader: string
): Promise<any> {
  
  const toolMapping: Record<string, string> = {
    'recon': 'recon',
    'webapp-scan': 'webapp-scan',
    'vuln-intel': 'vulnintel',
    'payload-generator': 'payload-generator',
    'wireless-scan': 'wireless-scan',
  };
  
  const functionName = toolMapping[tool];
  if (!functionName) {
    throw new Error(`Unknown tool: ${tool}`);
  }
  
  const { data, error } = await supabase.functions.invoke(functionName, {
    body: parameters,
    headers: { Authorization: authHeader }
  });
  
  if (error) throw error;
  return data;
}

async function analyzeStepResult(
  step: AttackStep, 
  result: any,
  apiKey: string
): Promise<any> {
  
  const systemPrompt = `You are a penetration testing analyst. Analyze attack results and identify vulnerabilities.
Respond with ONLY valid JSON (no markdown):
{
  "vulnerabilities": [{"type": "SQL Injection", "severity": "high", "location": "login form", "description": "..."}],
  "nextStepSuggestion": "Based on findings, recommend: ..."
}`;

  const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `Analyze this ${step.tool} result:\n${JSON.stringify(result, null, 2)}` }
      ],
      temperature: 0.3,
    }),
  });

  if (!response.ok) return { vulnerabilities: [], nextStepSuggestion: null };
  
  const data = await response.json();
  let analysisText = data.choices[0].message.content.trim();
  analysisText = analysisText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  
  try {
    return JSON.parse(analysisText);
  } catch {
    return { vulnerabilities: [], nextStepSuggestion: null };
  }
}

async function learnFromFailure(
  step: AttackStep,
  error: any,
  apiKey: string
): Promise<any> {
  
  const systemPrompt = `You are an AI that learns from penetration testing failures.
Analyze why an attack step failed and suggest adaptations.
Respond with ONLY valid JSON (no markdown):
{
  "insights": "Why it failed and what we learned",
  "retryWithDifferentApproach": true/false,
  "newParameters": {"modified": "parameters"}
}`;

  const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `Step: ${JSON.stringify(step)}\nError: ${error}` }
      ],
      temperature: 0.5,
    }),
  });

  if (!response.ok) {
    return {
      insights: 'Failed to analyze error',
      retryWithDifferentApproach: false,
      newParameters: step.parameters
    };
  }
  
  const data = await response.json();
  let learningText = data.choices[0].message.content.trim();
  learningText = learningText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
  
  try {
    return JSON.parse(learningText);
  } catch {
    return {
      insights: 'Failed to parse learning response',
      retryWithDifferentApproach: false,
      newParameters: step.parameters
    };
  }
}

async function storeAttackResults(
  chain: AttackChain,
  userId: string,
  supabase: any
) {
  // Use correct column names matching the security_audit_log table schema
  await supabase.from('security_audit_log').insert({
    user_id: userId,
    action: 'autonomous_attack',
    target: chain.target,
    module: 'autonomous_attack',
    result: JSON.stringify({
      objective: chain.objective,
      steps_executed: chain.currentStep,
      total_steps: chain.steps.length,
      findings_count: chain.findings.length,
      learnings: chain.learnings,
      status: chain.status
    })
  });

  // Also store in scan_history for reporting
  await supabase.from('scan_history').insert({
    module: 'autonomous_attack',
    scan_type: 'autonomous',
    target: chain.target,
    status: chain.status,
    findings_count: chain.findings.length,
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    report: {
      objective: chain.objective,
      steps: chain.steps,
      findings: chain.findings,
      learnings: chain.learnings
    }
  });
}
