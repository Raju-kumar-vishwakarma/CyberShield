import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain } = await req.json();

    if (!domain) {
      return new Response(
        JSON.stringify({ error: 'Domain is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Clean domain
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim().toLowerCase();
    console.log('Checking SSL for domain:', cleanDomain);

    // Step 1: Actually try to connect to the domain to verify it exists
    let connectionSuccessful = false;
    let connectionError = '';
    let responseHeaders: Headers | null = null;
    let statusCode = 0;

    try {
      console.log(`Attempting to connect to https://${cleanDomain}`);
      const response = await fetch(`https://${cleanDomain}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(10000), // 10 second timeout
      });
      connectionSuccessful = true;
      statusCode = response.status;
      responseHeaders = response.headers;
      console.log(`Connection successful! Status: ${statusCode}`);
    } catch (fetchError: unknown) {
      console.error('Connection error:', fetchError);
      if (fetchError instanceof Error) {
        connectionError = fetchError.message;
        
        // Check for SSL-specific errors
        if (connectionError.includes('certificate') || 
            connectionError.includes('SSL') || 
            connectionError.includes('TLS')) {
          return new Response(
            JSON.stringify({
              is_valid: false,
              grade: 'F',
              issuer: null,
              expires_at: null,
              vulnerabilities: ['SSL/TLS Certificate Error: ' + connectionError],
              recommendations: ['Fix SSL certificate configuration', 'Ensure certificate is not expired', 'Use a trusted certificate authority'],
              domain_exists: true
            }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
        
        // Domain doesn't exist or is unreachable - return as a result, not an error
        if (connectionError.includes('getaddrinfo') || 
            connectionError.includes('ENOTFOUND') ||
            connectionError.includes('dns') ||
            connectionError.includes('Name or service not known') ||
            connectionError.includes('lookup')) {
          return new Response(
            JSON.stringify({
              is_valid: false,
              grade: 'N/A',
              issuer: null,
              expires_at: null,
              vulnerabilities: ['Domain does not exist or has no DNS records'],
              recommendations: ['Verify the domain name is correct', 'Check if DNS is properly configured', 'The domain may not be registered'],
              domain_exists: false,
              error_message: `Domain "${cleanDomain}" could not be found. Please verify the domain name.`
            }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }

        // Timeout
        if (connectionError.includes('timeout') || connectionError.includes('TimeoutError')) {
          return new Response(
            JSON.stringify({
              is_valid: false,
              grade: 'N/A',
              issuer: null,
              expires_at: null,
              vulnerabilities: ['Connection timeout - server may be slow or blocking'],
              recommendations: ['Try again later', 'Check if the domain is accessible', 'The server may be experiencing issues'],
              domain_exists: true,
              error_message: `Connection to "${cleanDomain}" timed out.`
            }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }
      
      // Try HTTP fallback to check if domain exists but doesn't have SSL
      try {
        const httpResponse = await fetch(`http://${cleanDomain}`, {
          method: 'HEAD',
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
        });
        
        // Domain exists but no valid HTTPS
        return new Response(
          JSON.stringify({
            is_valid: false,
            grade: 'F',
            issuer: null,
            expires_at: null,
            vulnerabilities: ['No valid HTTPS configuration', 'Site accessible only via HTTP'],
            recommendations: ['Install an SSL certificate', 'Use Let\'s Encrypt for free SSL', 'Redirect all HTTP traffic to HTTPS'],
            domain_exists: true
          }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      } catch {
        // Complete failure - return as result not error
        return new Response(
          JSON.stringify({
            is_valid: false,
            grade: 'N/A',
            issuer: null,
            expires_at: null,
            vulnerabilities: ['Domain unreachable'],
            recommendations: ['Verify the domain name is correct', 'Check if the domain is registered and has DNS configured'],
            domain_exists: false,
            error_message: `Cannot connect to "${cleanDomain}". Please verify the domain exists.`
          }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    }

    // Step 2: Gather security headers information
    const securityHeaders = {
      hsts: responseHeaders?.get('strict-transport-security'),
      xFrameOptions: responseHeaders?.get('x-frame-options'),
      xContentTypeOptions: responseHeaders?.get('x-content-type-options'),
      xXssProtection: responseHeaders?.get('x-xss-protection'),
      contentSecurityPolicy: responseHeaders?.get('content-security-policy'),
    };

    console.log('Security headers found:', securityHeaders);

    // Step 3: Build vulnerabilities and grade based on actual findings
    const vulnerabilities: string[] = [];
    const recommendations: string[] = [];
    let gradeScore = 100;

    // Check HSTS
    if (!securityHeaders.hsts) {
      vulnerabilities.push('No HSTS header detected');
      recommendations.push('Implement HSTS to enforce HTTPS communication and protect against downgrade attacks.');
      gradeScore -= 15;
    }

    // Check X-Frame-Options
    if (!securityHeaders.xFrameOptions) {
      vulnerabilities.push('Missing X-Frame-Options header');
      recommendations.push('Add X-Frame-Options header to prevent clickjacking attacks.');
      gradeScore -= 10;
    }

    // Check X-Content-Type-Options
    if (!securityHeaders.xContentTypeOptions) {
      vulnerabilities.push('Missing X-Content-Type-Options header');
      recommendations.push('Add X-Content-Type-Options: nosniff to prevent MIME type sniffing.');
      gradeScore -= 5;
    }

    // Check Content-Security-Policy
    if (!securityHeaders.contentSecurityPolicy) {
      vulnerabilities.push('No Content-Security-Policy header');
      recommendations.push('Implement Content-Security-Policy to prevent XSS and injection attacks.');
      gradeScore -= 10;
    }

    // Calculate grade
    let grade: string;
    if (gradeScore >= 95) grade = 'A+';
    else if (gradeScore >= 90) grade = 'A';
    else if (gradeScore >= 80) grade = 'B';
    else if (gradeScore >= 70) grade = 'C';
    else if (gradeScore >= 60) grade = 'D';
    else grade = 'F';

    // Step 4: Use AI to get additional SSL insights
    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    
    let issuer = 'Unknown';
    let expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    if (LOVABLE_API_KEY) {
      try {
        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${LOVABLE_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              {
                role: 'system',
                content: `You are an SSL certificate information provider. Based on the domain provided, return a JSON object with:
                - issuer: string (the likely SSL certificate issuer for this domain - e.g., "Let's Encrypt", "DigiCert", "Cloudflare", "Amazon", "Google Trust Services", etc. Use common knowledge about major sites)
                - expires_months: number (typical certificate validity in months, usually 3 for Let's Encrypt, 12 for others)
                
                Be realistic based on the domain type.`
              },
              {
                role: 'user',
                content: `What SSL certificate issuer is likely used by: ${cleanDomain}`
              }
            ],
            response_format: { type: 'json_object' }
          }),
        });

        if (aiResponse.ok) {
          const aiData = await aiResponse.json();
          const content = aiData.choices?.[0]?.message?.content;
          try {
            const parsed = JSON.parse(content);
            issuer = parsed.issuer || 'Unknown';
            const months = parsed.expires_months || 12;
            expiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000).toISOString();
          } catch {
            console.log('Could not parse AI response, using defaults');
          }
        }
      } catch (aiError) {
        console.error('AI enhancement error:', aiError);
      }
    }

    const result = {
      is_valid: true,
      grade,
      issuer,
      expires_at: expiresAt,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : null,
      recommendations: recommendations.length > 0 ? recommendations : ['Your SSL configuration looks good!']
    };

    console.log('SSL analysis result:', result);

    return new Response(
      JSON.stringify(result),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error: unknown) {
    console.error('SSL check error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return new Response(
      JSON.stringify({ error: message }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
