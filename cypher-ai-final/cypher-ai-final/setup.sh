#!/bin/bash
# ============================================================
# CYPHER AI — Setup & Push to GitHub
# Heavy1981/cypher-ai
# ============================================================

set -e
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}🛡️  CYPHER AI — Setup Script${NC}"
echo -e "${CYAN}================================${NC}"
echo ""

GITHUB_USER="Heavy1981"
REPO_NAME="cypher-ai"

# ── 1. Check git ──────────────────────────────────────────────
command -v git >/dev/null 2>&1 || { echo -e "${RED}Git não encontrado. Instale em https://git-scm.com${NC}"; exit 1; }

# ── 2. Init git ───────────────────────────────────────────────
echo -e "${YELLOW}→ Inicializando repositório Git...${NC}"
git init
git add -A
git commit -m "🛡️ Initial commit — CYPHER AI Security Platform

- Frontend (Vercel): Dashboard + Chat AI + Relatórios com gráficos
- Backend (Railway): FastAPI + integrações SIEM/EDR/FW
- Supabase: Schema completo com 13 tabelas + RLS
- CI/CD: GitHub Actions automático
- Integrações: Splunk, CrowdStrike, SentinelOne, FortiGate, Palo Alto, AWS, Azure"

# ── 3. Add remote ─────────────────────────────────────────────
echo -e "${YELLOW}→ Configurando remote GitHub...${NC}"
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${GITHUB_USER}/${REPO_NAME}.git"

echo ""
echo -e "${GREEN}✅ Repositório local pronto!${NC}"
echo ""
echo -e "${CYAN}📋 PRÓXIMOS PASSOS:${NC}"
echo ""
echo -e "${YELLOW}1. Crie o repositório no GitHub:${NC}"
echo "   → https://github.com/new"
echo "   → Nome: ${REPO_NAME}"
echo "   → Visibilidade: Private (recomendado)"
echo "   → NÃO inicializar com README"
echo ""
echo -e "${YELLOW}2. Push para o GitHub:${NC}"
echo "   git push -u origin main"
echo ""
echo -e "${YELLOW}3. Configure o Supabase:${NC}"
echo "   → https://supabase.com → New Project → cypher-ai"
echo "   → SQL Editor → cole o conteúdo de supabase/migrations/001_schema.sql"
echo ""
echo -e "${YELLOW}4. Deploy do Backend no Railway:${NC}"
echo "   → https://railway.app → New → Deploy from GitHub"
echo "   → Selecione: ${GITHUB_USER}/${REPO_NAME} → pasta backend/"
echo "   → Adicione as variáveis do backend/.env.example"
echo ""
echo -e "${YELLOW}5. Deploy do Frontend no Vercel:${NC}"
echo "   → https://vercel.com → New Project → Import ${GITHUB_USER}/${REPO_NAME}"
echo "   → Root Directory: frontend/"
echo "   → Adicione: VITE_API_URL=https://sua-url.railway.app"
echo ""
echo -e "${YELLOW}6. Configure os Secrets do GitHub Actions:${NC}"
echo "   → https://github.com/${GITHUB_USER}/${REPO_NAME}/settings/secrets/actions"
echo "   → ANTHROPIC_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_KEY"
echo "   → JWT_SECRET, VERCEL_TOKEN, RAILWAY_TOKEN"
echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}🚀 CYPHER AI estará em produção!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
