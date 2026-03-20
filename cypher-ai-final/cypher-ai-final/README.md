# 🛡️ CYPHER AI — Security Incident Response Platform

> Plataforma SaaS de resposta a incidentes com IA, integrações SIEM/EDR/XDR e relatórios automáticos.

[![Deploy Frontend](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Heavy1981/cypher-ai)

---

## Stack

| Camada | Tecnologia |
|---|---|
| Frontend | HTML/JS/CSS estático — Vercel |
| Backend API | Python FastAPI — Railway |
| Banco de Dados | Supabase (PostgreSQL) |
| AI | Anthropic Claude API |
| CI/CD | GitHub Actions |

---

## Setup em 10 minutos

### 1. Clone o repositório

```bash
git clone https://github.com/Heavy1981/cypher-ai.git
cd cypher-ai
```

### 2. Configure o Supabase

1. Acesse [supabase.com](https://supabase.com) → New Project → Nome: `cypher-ai`
2. Em **SQL Editor**, execute o arquivo `supabase/migrations/001_schema.sql`
3. Copie as credenciais em **Settings → API**:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_KEY`

### 3. Deploy do Backend no Railway

1. Acesse [railway.app](https://railway.app) → New Project → Deploy from GitHub
2. Selecione o repositório `cypher-ai`, pasta `backend/`
3. Configure as variáveis de ambiente:

```env
ANTHROPIC_API_KEY=sk-ant-...
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJ...
JWT_SECRET=gere-uma-string-aleatoria-aqui
APP_ENV=production
```

4. Anote a URL gerada: `https://cypher-ai-backend.up.railway.app`

### 4. Deploy do Frontend no Vercel

1. Acesse [vercel.com](https://vercel.com) → New Project → Import `cypher-ai`
2. **Root Directory**: `frontend/`
3. Configure as variáveis de ambiente:

```env
VITE_API_URL=https://cypher-ai-backend.up.railway.app
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=eyJ...
```

4. Deploy! URL: `https://cypher-ai.vercel.app`

### 5. Configurar Secrets no GitHub (CI/CD automático)

Em `github.com/Heavy1981/cypher-ai` → Settings → Secrets and variables → Actions:

```
ANTHROPIC_API_KEY
SUPABASE_URL
SUPABASE_SERVICE_KEY
JWT_SECRET
VERCEL_TOKEN
VERCEL_ORG_ID
VERCEL_PROJECT_ID
RAILWAY_TOKEN
```

---

## Desenvolvimento local

```bash
# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env   # preencha as variáveis
uvicorn app.main:app --reload

# Frontend
cd frontend
# abra index.html no browser ou use live-server
npx live-server .
```

---

## Estrutura do Projeto

```
cypher-ai/
├── frontend/
│   ├── index.html          # Dashboard principal + chat AI
│   ├── relatorio.html      # Gerador de relatórios com gráficos
│   ├── login.html          # Tela de login
│   ├── src/
│   │   ├── app.js          # Lógica principal
│   │   ├── relatorio.js    # Lógica de relatórios
│   │   ├── api.js          # Client HTTP → Railway API
│   │   └── auth.js         # Auth Supabase
│   └── public/
│       ├── logo.svg        # Logo CYPHER AI
│       └── icon.svg        # Ícone quadrado
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/            # Routers FastAPI
│   │   ├── core/           # Config, auth, security
│   │   ├── integrations/   # SIEM, EDR, FW connectors
│   │   ├── models/         # ORM models
│   │   ├── services/       # AI service, playbooks
│   │   └── workers/        # Celery tasks
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── supabase/
│   └── migrations/
│       └── 001_schema.sql  # Schema completo
├── .github/
│   └── workflows/
│       ├── deploy-frontend.yml
│       └── deploy-backend.yml
└── README.md
```

---

## Funcionalidades

- ✅ Chat AI em tempo real com Claude (DFIR especializado)
- ✅ Gestão de incidentes multi-tenant
- ✅ Relatórios com 6 gráficos + correlação host/usuário/empresa
- ✅ 10 integrações: Splunk, CrowdStrike, Fortinet, AWS, Azure...
- ✅ Automações: isolar host, bloquear IP, criar ticket Jira
- ✅ Playbooks de resposta (Ransomware, Phishing, DDoS...)
- ✅ IOC enrichment via VirusTotal
- ✅ Exportar relatório PDF
- ✅ MFA/TOTP

---

Feito com ❤️ por **Heavy1981** · Powered by CYPHER AI
