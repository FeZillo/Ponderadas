# ASIS API — SDK de Integração Python

## Visão Geral

A **ASIS API** (by Sankhya / Kolossus) é a interface programática da solução Kolossus para processar, auditar e extrair resultados de arquivos SPED. Este SDK implementa o fluxo completo de integração em Python, cobrindo:

- Autenticação JWT com renovação automática
- Upload assíncrono de arquivos SPED
- Polling do processo com backoff exponencial
- Consulta de resultados sintéticos e analíticos
- Controle de qualidade com métricas de latência e SLA

---

## a) Estrutura de Integração

### Arquitetura em Camadas

```
┌─────────────────────────────────────────────┐
│         CAMADA DE APRESENTAÇÃO              │  → App / CLI chamadora
├─────────────────────────────────────────────┤
│      CAMADA DE ORQUESTRAÇÃO                 │  → AsisFluxoIntegracao
├─────────────────────────────────────────────┤
│      CAMADA DE SERVIÇOS                     │  → AsisClient
├─────────────────────────────────────────────┤
│   CAMADA DE SEGURANÇA                       │  → JwtAuth
├─────────────────────────────────────────────┤
│   CAMADA DE QUALIDADE                       │  → QualityController
├─────────────────────────────────────────────┤
│   CAMADA DE TRANSPORTE                      │  → requests + HTTPAdapter
└─────────────────────────────────────────────┘
```

| Camada | Classe / Módulo | Responsabilidade |
|---|---|---|
| Apresentação | App / CLI | Código que chama o SDK (sistema externo) |
| Orquestração | `AsisFluxoIntegracao` | Coordena as 6 etapas do fluxo em sequência |
| Segurança | `JwtAuth` | Geração, validação e renovação de tokens JWT HS256 |
| Serviços | `AsisClient` | Executa chamadas HTTP aos endpoints da API |
| Qualidade | `QualityController` | Latência, SLA, versões, histórico e relatório |
| Transporte | `requests + HTTPAdapter` | HTTPS com retry 3x, backoff exponencial, TLS |

### Componentes Principais

#### Entidades da API

- **Aplicativo** — entidade que define quem executa as chamadas na API
- **Conta** — agrupa Processos, Arquivos e Resultados; isola clientes/organizações
- **Processo** — criado a cada upload, execução assíncrona com estado
- **Resultado Sintético** — lista de auditorias com diagnóstico e contagens
- **Resultado Analítico** — itens individuais de cada auditoria

#### Ambientes

| Ambiente | Upload | Core | Resultado |
|---|---|---|---|
| Staging | `upload.stg.asistaxtech.com.br` | `core.stg.asistaxtech.com.br` | `resultado.stg.asistaxtech.com.br` |
| Produção | `upload.asistaxtech.com.br` | `core.asistaxtech.com.br` | `resultado.asistaxtech.com.br` |

#### Hardware e Software

| Componente | Tecnologia |
|---|---|
| Protocolo | HTTPS / REST |
| Versão da API | v1 |
| Versão do SDK | 1.0.0 |
| Linguagem | Python 3.8+ |
| Autenticação | JWT HS256 |
| Biblioteca HTTP | `requests` + `urllib3` |
| Retry HTTP | 3 tentativas, backoff 1.5x, status 500/502/503/504 |

### Arquivos do Projeto

| Arquivo | Conteúdo |
|---|---|
| `asis_client.py` | SDK completo: `JwtAuth`, `QualityController`, `AsisClient`, `AsisFluxoIntegracao` e exceções |
| `test_asis.py` | Suite com 35 testes unitários cobrindo todas as camadas |
| `exemplo_uso.py` | Demonstração do fluxo completo com tratamento de exceções |

---

## b) Controle de Qualidade de Integração

### Fluxo Completo — 6 Etapas

Ao chamar `AsisFluxoIntegracao.executar(caminho_arquivo)`, o SDK executa automaticamente:

| Etapa | Ação | Endpoint | Timeout |
|---|---|---|---|
| 1 | Verificar JWT | — (local) | — |
| 2 | Upload do arquivo | `POST /api/v1/upload` | 120s |
| 3 | Polling do processo | `GET /api/v1/processo/{id}` | 10s/tentativa · máx 60x |
| 4 | Resultados sintéticos | `GET /api/v1/resultado/processo/{id}` | 30s |
| 5 | Resultados analíticos | `GET /api/v1/resultado/processo/{id}/auditoria/{aid}` | 30s |
| 6 | Relatório de qualidade | — (local) | — |

```
[App] ──► [1. JWT Auth] ──► [2. Upload] ──► [3. Polling] ──► [4. Sintético] ──► [5. Analítico] ──► [6. QC Report]
                                                  │
                                          aguarda status 201
                                      (backoff 5s → 30s, máx 60x)
```

### Autenticação JWT

Cada requisição carrega três camadas de autenticação:

```http
account-key:   <ACCOUNT_KEY>
app-key:       <APP_KEY>
Authorization: Bearer <JWT_TOKEN>
X-SDK-Version: 1.0.0
X-API-Version: v1
X-Request-ID:  <UUID único por requisição>
```

O payload do JWT contém:

```json
{
  "iss": "asis-sdk",
  "sub": "<account_key>",
  "iat": 1710000000,
  "exp": 1710003600,
  "jti": "<uuid4>",
  "account_key": "...",
  "app_key": "...",
  "sdk_version": "1.0.0",
  "api_version": "v1"
}
```

O token é renovado automaticamente quando restam menos de 30 segundos para expirar. Cada token possui um `jti` (JWT ID) único por UUID, impossibilitando reutilização.

### Métricas de Qualidade — `QualityController`

Toda requisição HTTP é instrumentada automaticamente:

| Métrica | Tipo | Descrição |
|---|---|---|
| Latência | `ms` (float) | Medida via `time.perf_counter()` |
| SLA | Alerta `WARNING` | Upload >5s · Processo >2s · Resultado >3s |
| Protocolo | string | `HTTPS/1.1` registrado por chamada |
| Versões | string | `SDK v1.0.0` e `API v1` em cada métrica |
| Taxa de sucesso | `%` (float) | Requisições HTTP < 400 / total |
| Histórico | `list[dict]` | Todas as chamadas com status, URL e método |
| Erros | `list[dict]` | Exceções com tipo, mensagem e timestamp ISO |

Exemplo do relatório gerado ao fim do fluxo:

```json
{
  "sdk_version": "1.0.0",
  "api_version": "v1",
  "protocolo": "HTTPS/REST",
  "total_requisicoes": 6,
  "sucesso": 6,
  "falhas": 0,
  "taxa_sucesso_pct": 100.0,
  "latencia_media_ms": 85.4,
  "latencia_max_ms": 210.3,
  "latencia_min_ms": 12.1
}
```

### Tratamento de Exceções

Todas as exceções são tipadas, possuem `codigo` HTTP, `timestamp` ISO e `detalhes` opcionais:

| Exceção | Código | Quando ocorre |
|---|---|---|
| `AsisAuthError` | 401 | JWT inválido, expirado ou credenciais incorretas |
| `AsisTimeoutError` | 408 | Timeout em requisição HTTP ou polling excedido |
| `AsisProcessoError` | 500 / 204 | Processo encerrou com erro ou foi cancelado |
| `AsisUploadError` | 413 | Arquivo excede tamanho ou resposta sem processo |
| `AsisArquivoError` | — | Arquivo inexistente ou vazio antes do upload |
| `AsisBaseError` | 503+ | Erros de conexão, recurso não encontrado (404), 5xx |

```python
try:
    resultado = fluxo.executar("sped_fiscal.txt")
except AsisAuthError as exc:
    print(f"Autenticação falhou [{exc.codigo}]: {exc}")
except AsisTimeoutError as exc:
    print(f"Timeout [{exc.codigo}]: {exc}")
except AsisProcessoError as exc:
    print(f"Processo com erro [{exc.codigo}]: {exc.detalhes}")
except AsisBaseError as exc:
    print(f"Erro genérico [{exc.codigo}]: {exc}")
```

---

## Instalação

```bash
pip install requests PyJWT
```

## Uso Rápido

```python
from asis_client import CredenciaisAsis, AsisClient, AsisFluxoIntegracao

credenciais = CredenciaisAsis(
    account_key="SUA_ACCOUNT_KEY",
    app_key="SUA_APP_KEY",
    jwt_secret="SEU_SEGREDO_JWT",
    jwt_expiracao_min=60,
)

cliente  = AsisClient(credenciais, ambiente="stg")
fluxo    = AsisFluxoIntegracao(cliente)
resultado = fluxo.executar("sped_fiscal.txt", max_analiticos=3)

print(resultado.resumo())
print(resultado.relatorio_qualidade)
```

## Executar os Testes

```bash
python test_asis.py
```

Resultado esperado:
```
Ran 35 tests in 0.134s
OK
Total: 35 | OK: 35 | Falhas: 0 | Erros: 0
```

---

*SDK ASIS API v1.0.0 · Protocolo HTTPS/REST · API v1 · Python 3.8+*
