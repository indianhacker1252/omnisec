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

async function callAI(systemPrompt: string, userMessage: string, apiKey: string): Promise<string> {
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
        { role: 'user', content: userMessage }
      ],
      temperature: 0.5,
      max_tokens: 2000,
    }),
  });

  if (!response.ok) {
    throw new Error(`AI error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
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
    if (!LOVABLE_API_KEY) {
      throw new Error('AI service not configured');
    }

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
  const systemPrompt = `You are an elite autonomous penetration testing AI. Generate attack chains for authorized security testing.

You MUST respond with ONLY a valid JSON object (no markdown, no explanation) defining an attack chain.

Available tools:
1. "recon" - Reconnaissance and target discovery
2. "webapp-scan" - Web application security scanning
3. "vuln-intel" - CVE and vulnerability intelligence

Respond with JSON in this exact format:
{
  "target": "${target}",
  "objective": "${objective}",
  "steps": [
    {"step": 1, "action": "Reconnaissance", "tool": "recon", "parameters": {"target": "${target}"}, "status": "pending"},
    {"step": 2, "action": "Vulnerability Scan", "tool": "webapp-scan", "parameters": {"target": "${target}"}, "status": "pending"},
    {"step": 3, "action": "Intelligence Gathering", "tool": "vuln-intel", "parameters": {"query": "${target}"}, "status": "pending"}
  ],
  "currentStep": 0,
  "status": "planning",
  "findings": [],
  "learnings": []
}`;

  try {
    const planText = await callAI(systemPrompt, 
      `Generate an attack chain for target: ${target} with objective: ${objective}. Respond with ONLY valid JSON.`,
      apiKey
    );
    
    const cleanText = planText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const attackChain = JSON.parse(cleanText);
    console.log('[Attack Plan Generated]:', JSON.stringify(attackChain, null, 2));
    return attackChain;
  } catch (error) {
    console.error('[Attack Plan Error]:', error);
    // Return a default attack chain
    return {
      target,
      objective,
      steps: [
        { step: 1, action: "Reconnaissance", tool: "recon", parameters: { target }, status: "pending" },
        { step: 2, action: "Web Application Scan", tool: "webapp-scan", parameters: { target }, status: "pending" },
        { step: 3, action: "Vulnerability Intelligence", tool: "vuln-intel", parameters: { query: target }, status: "pending" }
      ],
      currentStep: 0,
      status: "planning",
      findings: [],
      learnings: []
    };
  }
}

async function executeAttackChain(chain: AttackChain, supabase: any, authHeader: string, apiKey: string) {
  chain.status = 'executing';
  
  for (let i = 0; i < chain.steps.length; i++) {
    const step = chain.steps[i];
    chain.currentStep = i + 1;
    step.status = 'running';
    
    console.log(`[Executing Step ${step.step}] ${step.action}`);
    
    try {
      const result = await executeTool(step.tool, step.parameters, supabase, authHeader);
      step.result = result;
      step.status = 'success';
      
      const analysis = await analyzeStepResult(step, result, apiKey);
      
      if (analysis.vulnerabilities?.length > 0) {
        chain.findings.push(...analysis.vulnerabilities);
      }
      
      if (analysis.nextStepSuggestion) {
        chain.learnings.push(`Step ${step.step}: ${analysis.nextStepSuggestion}`);
      }
      
      console.log(`[Step ${step.step} Success]`, { findings: analysis.vulnerabilities?.length || 0 });
      
    } catch (error) {
      step.status = 'failed';
      step.error = error instanceof Error ? error.message : 'Unknown error';
      console.error(`[Step ${step.step} Failed]:`, error);
      
      const learning = await learnFromFailure(step, error, apiKey);
      step.learnings = learning.insights;
      chain.learnings.push(`Step ${step.step} failure: ${learning.insights}`);
    }
  }
  
  chain.status = 'completed';
}

async function executeTool(tool: string, parameters: Record<string, any>, supabase: any, authHeader: string): Promise<any> {
  const toolMapping: Record<string, string> = {
    'recon': 'recon',
    'webapp-scan': 'webapp-scan',
    'vuln-intel': 'vulnintel',
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

async function analyzeStepResult(step: AttackStep, result: any, apiKey: string): Promise<any> {
  try {
    const analysisText = await callAI(
      `You are a penetration testing analyst. Analyze results and identify vulnerabilities. Respond with ONLY valid JSON: {"vulnerabilities": [{"type": "string", "severity": "high|medium|low", "description": "string"}], "nextStepSuggestion": "string"}`,
      `Analyze this ${step.tool} result:\n${JSON.stringify(result, null, 2)}`,
      apiKey
    );

    const cleanText = analysisText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(cleanText);
  } catch {
    return { vulnerabilities: [], nextStepSuggestion: null };
  }
}

async function learnFromFailure(step: AttackStep, error: any, apiKey: string): Promise<any> {
  try {
    const learningText = await callAI(
      `Analyze penetration testing failures. Respond with ONLY valid JSON: {"insights": "string", "retryWithDifferentApproach": false, "newParameters": {}}`,
      `Step: ${JSON.stringify(step)}\nError: ${error}`,
      apiKey
    );

    const cleanText = learningText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(cleanText);
  } catch {
    return { insights: 'Analysis failed', retryWithDifferentApproach: false, newParameters: step.parameters };
  }
}

async function storeAttackResults(chain: AttackChain, userId: string, supabase: any) {
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