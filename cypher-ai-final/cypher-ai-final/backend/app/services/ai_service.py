"""
CYPHER AI Service
Wrapper para Claude API com prompts especializados em DFIR
"""
from typing import AsyncGenerator, Optional
import anthropic
from app.core.config import settings

client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """Você é o CYPHER AI, um analista sênior de segurança da informação especializado em Resposta a Incidentes e Forense Digital (DFIR). 

EXPERTISE:
- Frameworks: MITRE ATT&CK, NIST 800-61, SANS IR Process, PTES, OWASP
- Threat Intelligence: APT groups, TTPs, IOC analysis, threat hunting
- Forense Digital: análise de memória, disco, rede, logs, cloud forensics
- Malware Analysis: comportamento, evasão, persistência, C2 channels
- Compliance: LGPD, GDPR, ISO 27001, PCI-DSS, SOC2, HIPAA
- Cloud Security: AWS, Azure, GCP security posture

REGRAS DE CONDUTA:
1. Sempre priorize CONTENÇÃO antes de investigação
2. Preserve evidências — nunca destrua logs ou artifacts antes da análise forense
3. Documente TUDO com timestamps UTC
4. Classifique ameaças usando MITRE ATT&CK (Tática/Técnica/Sub-técnica)
5. Use escala de severidade: CRITICAL > HIGH > MEDIUM > LOW > INFO
6. Forneça IOCs estruturados (IP, hash, domínio, URL)
7. Recomende ações específicas, não genéricas
8. Considere blast radius — impacto lateral potencial
9. Identifique o kill chain stage (Recon → Weaponize → Deliver → Exploit → Install → C2 → Act)
10. Responda sempre em português brasileiro

FORMATO DE RESPOSTA:
- Use **negrito** para termos críticos e ações urgentes
- Use blocos de código para hashes, IPs, comandos, logs
- Numere passos de resposta
- Use seções claras quando a resposta for longa
- Seja direto — analistas precisam agir rápido

CONTEXTO TÉCNICO:
Você tem acesso ao contexto do incidente, alertas correlacionados, IOCs identificados e histórico de ações já executadas. Use essas informações para fornecer análises cada vez mais precisas."""


async def analyze_incident_stream(
    messages: list[dict],
    incident_context: dict,
    extra_context: Optional[str] = None,
) -> AsyncGenerator[str, None]:
    """Stream de análise de incidente em tempo real."""
    context_block = f"""
=== CONTEXTO DO INCIDENTE ===
ID: {incident_context.get('ref', 'N/A')}
Título: {incident_context.get('title', 'N/A')}
Severidade: {incident_context.get('severity', 'N/A').upper()}
Status: {incident_context.get('status', 'N/A')}
Cliente: {incident_context.get('client_name', 'N/A')}
Categoria: {incident_context.get('category', 'Não classificado')}
Hosts afetados: {', '.join(incident_context.get('affected_hosts', [])) or 'Não identificados'}
IPs suspeitos: {', '.join(incident_context.get('affected_ips', [])) or 'Nenhum'}
MITRE Tactics: {', '.join(incident_context.get('mitre_tactics', [])) or 'Não mapeado'}
IOCs identificados: {incident_context.get('ioc_count', 0)}
Ações executadas: {incident_context.get('action_count', 0)}
{extra_context or ''}
=== FIM DO CONTEXTO ===

"""
    # Injeta contexto no primeiro ou último user message
    enriched_messages = list(messages)
    if enriched_messages and enriched_messages[0]["role"] == "user":
        enriched_messages[0] = {
            **enriched_messages[0],
            "content": context_block + enriched_messages[0]["content"],
        }

    async with client.messages.stream(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=settings.AI_MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=enriched_messages,
    ) as stream:
        async for text in stream.text_stream:
            yield text


async def analyze_alert_batch(alerts: list[dict]) -> dict:
    """Analisa um lote de alertas e recomenda correlações e priorização."""
    alerts_text = "\n".join([
        f"- [{a.get('severity', '?').upper()}] {a.get('source', '?')}: {a.get('title', '?')} | {a.get('description', '')[:200]}"
        for a in alerts
    ])

    response = await client.messages.create(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Analise estes {len(alerts)} alertas e responda em JSON estruturado:

ALERTAS:
{alerts_text}

Responda APENAS com JSON válido no formato:
{{
  "risk_score": <0-100>,
  "priority": "critical|high|medium|low",
  "should_create_incident": true/false,
  "suggested_title": "...",
  "suggested_category": "ransomware|phishing|data_breach|ddos|malware|insider|apt|other",
  "mitre_tactics": ["..."],
  "mitre_techniques": ["T1xxx"],
  "correlated_alerts": [<indexes>],
  "summary": "...",
  "immediate_actions": ["...", "..."],
  "iocs_extracted": [{{"type": "ip|hash|domain", "value": "..."}}]
}}"""
        }],
    )

    import json
    text = response.content[0].text.strip()
    text = text.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "parse_failed", "raw": text}


async def generate_executive_report(incident: dict, messages: list[dict]) -> str:
    """Gera relatório executivo do incidente."""
    chat_summary = "\n".join([
        f"[{m['role'].upper()}]: {m['content'][:500]}"
        for m in messages[-20:]  # últimas 20 mensagens
    ])

    response = await client.messages.create(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=3000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Gere um RELATÓRIO EXECUTIVO completo para este incidente.

DADOS DO INCIDENTE:
{incident}

HISTÓRICO DE ANÁLISE (últimas interações):
{chat_summary}

O relatório deve conter:
1. SUMÁRIO EXECUTIVO (3-5 linhas para o C-Level)
2. LINHA DO TEMPO DO ATAQUE
3. SISTEMAS E DADOS AFETADOS
4. ANÁLISE TÉCNICA (causa raiz, TTPs, kill chain)
5. AÇÕES DE RESPOSTA EXECUTADAS
6. INDICADORES DE COMPROMETIMENTO (IOCs)
7. IMPACTO NO NEGÓCIO
8. RECOMENDAÇÕES DE REMEDIAÇÃO
9. LIÇÕES APRENDIDAS
10. PRÓXIMOS PASSOS

Seja técnico mas acessível. Inclua métricas e dados específicos quando disponíveis."""
        }],
    )
    return response.content[0].text


async def enrich_ioc(ioc_type: str, ioc_value: str, context: str = "") -> dict:
    """Análise contextual de IOC pelo modelo."""
    response = await client.messages.create(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Analise este IOC e responda em JSON:

Tipo: {ioc_type}
Valor: {ioc_value}
Contexto: {context}

Responda com JSON:
{{
  "risk_level": "critical|high|medium|low|unknown",
  "threat_category": "...",
  "known_threat_actor": "...",
  "recommended_action": "block|monitor|investigate|whitelist",
  "analysis": "...",
  "related_ttps": ["T1xxx"]
}}"""
        }],
    )
    import json
    text = response.content[0].text.strip().replace("```json", "").replace("```", "")
    try:
        return json.loads(text)
    except Exception:
        return {"analysis": response.content[0].text}


async def suggest_playbook(incident_data: dict) -> dict:
    """Sugere um playbook de resposta baseado no tipo de incidente."""
    response = await client.messages.create(
        model=settings.ANTHROPIC_MODEL,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"""Com base neste incidente, gere um playbook de resposta detalhado em JSON:

{incident_data}

Formato:
{{
  "name": "...",
  "description": "...",
  "steps": [
    {{
      "order": 1,
      "phase": "identification|containment|eradication|recovery|lessons_learned",
      "title": "...",
      "description": "...",
      "actions": [
        {{"type": "manual|automated", "tool": "...", "command": "...", "description": "..."}}
      ],
      "estimated_minutes": 15
    }}
  ]
}}"""
        }],
    )
    import json
    text = response.content[0].text.strip().replace("```json", "").replace("```", "")
    try:
        return json.loads(text)
    except Exception:
        return {"error": "parse_failed", "raw": response.content[0].text}
