# Plataforma de Identidade e SSO (nest-auth-mfa)

Plataforma de **autenticação única (SSO)** e **gestão de usuários** para empresas, construída sobre o [Amazon Cognito](https://aws.amazon.com/cognito/). Permite que um colaborador faça **login uma única vez** e acesse **várias aplicações** da empresa, com controle de acesso por **setor/grupo** e um **painel de administração** para gerenciar pessoas.

Este repositório é o **backend (API)** do sistema. A interface (portal) fica no projeto **[`portal-sso`](../portal-sso)**.

---

## Sumário

- [Visão geral do sistema](#visão-geral-do-sistema)
- [Como o sistema funciona](#como-o-sistema-funciona)
- [Componentes](#componentes)
- [Instalação e configuração](#instalação-e-configuração)
- [Primeiro acesso (administrador)](#primeiro-acesso-administrador)
- [Guia de uso (administrador)](#guia-de-uso-administrador)
- [Referência da API](#referência-da-api)
- [Segurança](#segurança)
- [Checklist para produção](#checklist-para-produção)

---

## Visão geral do sistema

| Papel | Responsável |
|---|---|
| **Identidade** (login, senha, MFA) | Amazon Cognito (Hosted UI) |
| **Regras de acesso / API** | Este backend (NestJS) |
| **Interface / portal** | [`portal-sso`](../portal-sso) (Next.js) |

```
┌──────────────┐  login    ┌─────────────────┐
│  portal-sso  │ ───────▶  │  Amazon Cognito │
│  (Next.js)   │ ◀───────  │  (login + MFA)  │
│  Portal/UI   │  tokens   └─────────────────┘
│              │
│  /apps       │  Bearer   ┌─────────────────┐
│  /admin      │ ───────▶  │  nest-auth-mfa  │  (valida token,
└──────────────┘           │  (esta API)     │   grupos, admin)
                           └─────────────────┘
```

- **Login único (SSO):** o colaborador autentica no Cognito e acessa todas as aplicações sem novo login.
- **Acesso por setor:** cada aplicação é visível apenas para os grupos autorizados (ex.: `vendas`, `financeiro`).
- **Provisionamento por administrador:** novos usuários são **convidados por e-mail** por um admin — não há cadastro aberto ao público.

---

## Como o sistema funciona

### 1. Login do colaborador
O usuário acessa o portal, clica em **Entrar** e é levado à tela de login do Cognito (e-mail + senha). Após autenticar, volta ao **portal de aplicações**, onde vê apenas os sistemas liberados para o seu setor.

### 2. Cadastro de novos usuários (convite)
O administrador, no painel `/admin`, informa **Nome + E-mail + Setor**. O sistema envia um **convite por e-mail** com uma senha temporária; a pessoa faz o primeiro login e define a própria senha. O administrador nunca conhece a senha do usuário.

### 3. Controle de acesso por grupo
Cada usuário pertence a um ou mais **grupos** (setores). Cada aplicação declara quais grupos podem acessá-la. O sistema mostra/oculta as aplicações conforme os grupos do usuário, e a API **bloqueia** no servidor quem não tem permissão.

---

## Componentes

```
nest-auth-mfa/                     # Backend (esta pasta)
├── src/
│   ├── auth/
│   │   ├── controllers/           # Endpoints de autenticação e administração
│   │   ├── services/              # Integração com o Amazon Cognito
│   │   ├── guards/                # Validação de token e de grupos (RBAC)
│   │   ├── decorators/            # @Groups() para proteger rotas por setor
│   │   └── dto/                   # Validação de entrada
│   ├── common/filters/            # Tratamento global de erros
│   ├── setup-pool.ts              # Provisiona o ambiente Cognito (1x)
│   └── seed-admin.ts              # Cria o primeiro administrador (1x)
portal-sso/                        # Frontend (projeto separado)
```

---

## Instalação e configuração

### Pré-requisitos
- Node.js 20+
- Uma conta AWS com credenciais IAM com a permissão **AmazonCognitoPowerUser**

### 1. Instalar dependências
```bash
npm install
```

### 2. Configurar as credenciais AWS
Crie um arquivo `.env` na raiz com as credenciais da AWS:
```env
AWS_REGION=sa-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

### 3. Provisionar o ambiente Cognito (uma vez)
O script abaixo cria, de forma automática, o **User Pool** (login por e-mail), o **App Client**, o **domínio** de login e os **grupos** padrão:

```bash
npm run setup:pool -- <prefixo-de-dominio>
# ex.: npm run setup:pool -- minha-empresa-sso
```

Ao final, ele imprime os valores para completar o `.env`:
```env
COGNITO_USER_POOL_ID=...
COGNITO_CLIENT_ID=...
COGNITO_CLIENT_SECRET=...
COGNITO_ALLOWED_CLIENT_IDS=...
```

| Variável | Obrigatória | Descrição |
|---|---|---|
| `AWS_REGION` | Não | Região AWS (padrão: `sa-east-1`). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Sim | Credenciais IAM (permissão Cognito). |
| `COGNITO_USER_POOL_ID` | Sim | ID do User Pool. |
| `COGNITO_CLIENT_ID` / `COGNITO_CLIENT_SECRET` | Sim | App Client e seu secret. |
| `COGNITO_ALLOWED_CLIENT_IDS` | Sim | App Clients aceitos pela API (separados por vírgula). |
| `COGNITO_DEFAULT_GROUP` | Não | Grupo atribuído automaticamente a novos cadastros. |
| `PORT` | Não | Porta HTTP (padrão: `3000`). |
| `CORS_ORIGINS` | Não | Origens permitidas para CORS (separadas por vírgula). |

### 4. Executar
```bash
npm run start:dev      # desenvolvimento (porta 3000)
npm run start:prod     # produção
```

---

## Primeiro acesso (administrador)

Toda plataforma precisa de um **primeiro administrador** — quem implanta o sistema o cria uma vez:

```bash
npm run seed:admin -- email-do-dono@empresa.com
```

Isso cria o grupo `admin` (se necessário) e promove esse usuário. A partir daí, **todo o resto é feito pelo painel** `/admin` — não é preciso mexer em scripts de novo.

> O usuário precisa existir (ter sido convidado/logado ao menos uma vez) para ser promovido. Após promover, ele deve sair e entrar novamente para o novo papel valer.

---

## Guia de uso (administrador)

No portal, o administrador vê o botão **🛠️ Admin** e acessa o painel, onde pode:

- **Convidar usuário** — informar Nome, E-mail e Setor. A pessoa recebe o convite por e-mail e define a senha no primeiro acesso.
- **Vincular/remover de um grupo** — mudar o setor de um usuário existente.
- **Ver os membros** de cada grupo.

Os grupos padrão criados são: `colaboradores`, `vendas`, `financeiro`, `admin`. Novos grupos podem ser criados pela API.

---

## Referência da API

Base: `http://localhost:3000`

### Saúde
| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/` | Status da API. |

### Recursos protegidos
Exigem `Authorization: Bearer <access_token>` válido do Cognito.

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| `GET` | `/me` | Autenticado | Dados do usuário do token. |

### Administração (somente grupo `admin`)
| Método | Rota | Corpo |
|---|---|---|
| `POST` | `/auth/admin/create-user` | `{ name, email, group? }` — envia convite |
| `POST` | `/auth/admin/groups` | `{ name, description? }` — cria grupo |
| `POST` | `/auth/admin/groups/add-user` | `{ email, group }` |
| `POST` | `/auth/admin/groups/remove-user` | `{ email, group }` |
| `GET` | `/auth/admin/groups/:group/users` | — lista membros |

### Autenticação programática (opcional)
Endpoints REST para integração direta (sem o Hosted UI): `POST /auth/login`, `/auth/refresh`, `/auth/forgot-password`, `/auth/reset-password`, entre outros. O fluxo recomendado para o portal é o Hosted UI (ver `portal-sso`).

---

## Segurança

- **Validação de token (JWKS):** todas as rotas protegidas verificam assinatura, expiração, emissor e App Client do token (`JwtAuthGuard`).
- **Controle de acesso por grupo (RBAC):** o decorator `@Groups('admin')` + `GroupsGuard` bloqueiam no servidor — a interface apenas oculta, o backend recusa de fato.
- **Rate limiting** global (`@nestjs/throttler`) e **cabeçalhos de segurança** (`helmet`).
- **Validação de entrada** com `class-validator` (`ValidationPipe` global).
- **Senhas:** geridas pelo Cognito; o administrador nunca tem acesso a elas.

---

## Checklist para produção

- [ ] **E-mail:** conectar o **Amazon SES** ao Cognito (o envio padrão tem limite baixo e é só para testes).
- [ ] **MFA:** habilitar MFA (SMS ou app autenticador) no User Pool, conforme a política da empresa.
- [ ] **Autocadastro:** manter o autorregistro **desligado** (modelo de provisionamento por administrador).
- [ ] **Credenciais:** usar **IAM Role** em vez de chaves de acesso quando hospedado na AWS.
- [ ] **HTTPS e CORS:** configurar `CORS_ORIGINS` com os domínios de produção.
- [ ] **Federação (opcional):** integrar o Cognito ao diretório corporativo (Azure AD / Google Workspace) via SAML/OIDC.

---

## Testes
```bash
npm run test       # unitários
npm run test:e2e   # end-to-end
npm run test:cov   # cobertura
```
