"""
======================================================================
ASIS API - Cliente de Integração Completo
======================================================================
Módulo principal de integração com a ASIS API (by Sankhya / Kolossus).

Arquitetura em Camadas:
  ┌─────────────────────────────────────────────┐
  │         CAMADA DE APRESENTAÇÃO              │  → CLI / App chamadora
  ├─────────────────────────────────────────────┤
  │      CAMADA DE ORQUESTRAÇÃO (Fluxo)         │  → AsisFluxoIntegracao
  ├─────────────────────────────────────────────┤
  │      CAMADA DE SERVIÇOS (Client)            │  → AsisClient
  ├─────────────────────────────────────────────┤
  │   CAMADA DE SEGURANÇA (Auth / JWT)          │  → JwtAuth
  ├─────────────────────────────────────────────┤
  │   CAMADA DE QUALIDADE (QC / Monitor)        │  → QualityController
  ├─────────────────────────────────────────────┤
  │   CAMADA DE TRANSPORTE (HTTP / requests)    │  → requests + urllib3
  └─────────────────────────────────────────────┘

Protocolo  : HTTPS / REST
Versão API : v1
Versão SDK : 1.0.0
Autor      : Grupo de Integração
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jwt           # PyJWT
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ──────────────────────────────────────────────
# Configuração de logging
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("asis.client")

# ──────────────────────────────────────────────
# Constantes e Configurações
# ──────────────────────────────────────────────
SDK_VERSION = "1.0.0"
API_VERSION = "v1"
AMBIENTE_STG = "stg"
AMBIENTE_PROD = "prod"

BASE_URLS: Dict[str, Dict[str, str]] = {
    AMBIENTE_STG: {
        "upload": "https://upload.stg.asistaxtech.com.br",
        "core":   "https://core.stg.asistaxtech.com.br",
        "result": "https://resultado.stg.asistaxtech.com.br",
    },
    AMBIENTE_PROD: {
        "upload": "https://upload.asistaxtech.com.br",
        "core":   "https://core.asistaxtech.com.br",
        "result": "https://resultado.asistaxtech.com.br",
    },
}

# Timeouts (segundos)
TIMEOUT_UPLOAD  = 120
TIMEOUT_DEFAULT = 30
TIMEOUT_POLL    = 10

# Polling de processo
POLL_INTERVALO_INICIAL = 5   # seg
POLL_INTERVALO_MAX     = 30  # seg
POLL_MAX_TENTATIVAS    = 60

# Código de status do processo (conforme API ASIS)
class StatusProcesso(Enum):
    AGUARDANDO   = 100
    PROCESSANDO  = 150
    CONCLUIDO    = 201
    ERRO         = 500
    CANCELADO    = 204

# ──────────────────────────────────────────────
# Exceções personalizadas
# ──────────────────────────────────────────────
class AsisBaseError(Exception):
    """Erro base do SDK ASIS."""
    def __init__(self, mensagem: str, codigo: Optional[int] = None, detalhes: Any = None):
        super().__init__(mensagem)
        self.codigo   = codigo
        self.detalhes = detalhes
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def __str__(self):
        base = super().__str__()
        return f"[{self.timestamp}] {base} (código={self.codigo})"


class AsisAuthError(AsisBaseError):
    """Falha de autenticação / JWT inválido ou expirado."""


class AsisUploadError(AsisBaseError):
    """Erro durante o upload de arquivo."""


class AsisTimeoutError(AsisBaseError):
    """Timeout de requisição ou polling excedido."""


class AsisProcessoError(AsisBaseError):
    """Erro no processamento assíncrono do processo."""


class AsisResultadoError(AsisBaseError):
    """Erro ao consultar resultados."""


class AsisArquivoError(AsisBaseError):
    """Problema com o arquivo a ser enviado."""


# ══════════════════════════════════════════════
# CAMADA DE SEGURANÇA — Autenticação JWT
# ══════════════════════════════════════════════
@dataclass
class CredenciaisAsis:
    """Credenciais de acesso à ASIS API."""
    account_key: str
    app_key: str
    jwt_secret: str           # Segredo compartilhado para assinar o JWT
    jwt_algoritmo: str = "HS256"
    jwt_expiracao_min: int = 60   # minutos de validade do token


@dataclass
class TokenJWT:
    """Token JWT gerado e seus metadados."""
    valor: str
    emitido_em: datetime
    expira_em: datetime
    jti: str  # JWT ID único por token

    def esta_valido(self, margem_seg: int = 30) -> bool:
        agora = datetime.now(timezone.utc)
        return agora < (self.expira_em - timedelta(seconds=margem_seg))

    def tempo_restante(self) -> float:
        return (self.expira_em - datetime.now(timezone.utc)).total_seconds()


class JwtAuth:
    """
    Gerenciador de autenticação JWT para a ASIS API.

    Fluxo:
      1. Gera token JWT assinado com account-key + app-key no payload
      2. Injeta o token em cada requisição HTTP (header Authorization)
      3. Renova automaticamente quando próximo da expiração
    """

    def __init__(self, credenciais: CredenciaisAsis):
        self._cred = credenciais
        self._token: Optional[TokenJWT] = None
        logger.info("JwtAuth inicializado. Algoritmo: %s | Validade: %d min",
                    credenciais.jwt_algoritmo, credenciais.jwt_expiracao_min)

    def _gerar_token(self) -> TokenJWT:
        agora     = datetime.now(timezone.utc)
        expira_em = agora + timedelta(minutes=self._cred.jwt_expiracao_min)
        jti       = str(uuid.uuid4())

        payload = {
            "iss":         "asis-sdk",
            "sub":         self._cred.account_key,
            "iat":         int(agora.timestamp()),
            "exp":         int(expira_em.timestamp()),
            "jti":         jti,
            "account_key": self._cred.account_key,
            "app_key":     self._cred.app_key,
            "sdk_version": SDK_VERSION,
            "api_version": API_VERSION,
        }

        valor = jwt.encode(
            payload,
            self._cred.jwt_secret,
            algorithm=self._cred.jwt_algoritmo,
        )

        token = TokenJWT(
            valor=valor,
            emitido_em=agora,
            expira_em=expira_em,
            jti=jti,
        )
        logger.info("Novo JWT gerado. JTI=%s | Expira em: %s", jti, expira_em.isoformat())
        return token

    def obter_token(self) -> str:
        """Retorna token válido, gerando/renovando se necessário."""
        if self._token is None or not self._token.esta_valido():
            logger.info("Token ausente ou expirado. Renovando...")
            self._token = self._gerar_token()
        return self._token.valor

    def validar_token(self, token_str: str) -> Dict[str, Any]:
        """Valida e decodifica um JWT, lançando AsisAuthError em caso de falha."""
        try:
            payload = jwt.decode(
                token_str,
                self._cred.jwt_secret,
                algorithms=[self._cred.jwt_algoritmo],
            )
            logger.debug("JWT validado com sucesso. JTI=%s", payload.get("jti"))
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise AsisAuthError("Token JWT expirado.", codigo=401) from exc
        except jwt.InvalidTokenError as exc:
            raise AsisAuthError(f"Token JWT inválido: {exc}", codigo=401) from exc

    def headers_autenticados(self) -> Dict[str, str]:
        """Retorna headers HTTP com autenticação ASIS + JWT Bearer."""
        return {
            "account-key":    self._cred.account_key,
            "app-key":        self._cred.app_key,
            "Authorization":  f"Bearer {self.obter_token()}",
            "X-SDK-Version":  SDK_VERSION,
            "X-API-Version":  API_VERSION,
            "X-Request-ID":   str(uuid.uuid4()),
            "Content-Type":   "application/json",
        }


# ══════════════════════════════════════════════
# CAMADA DE QUALIDADE — QualityController
# ══════════════════════════════════════════════
@dataclass
class MetricaRequisicao:
    """Registra dados de qualidade de uma única requisição HTTP."""
    request_id: str
    metodo: str
    url: str
    inicio: float         = field(default_factory=time.perf_counter)
    fim: Optional[float]  = None
    status_http: Optional[int] = None
    erro: Optional[str]   = None
    tentativas: int       = 1
    protocolo: str        = "HTTPS/1.1"

    @property
    def duracao_ms(self) -> Optional[float]:
        if self.fim:
            return round((self.fim - self.inicio) * 1000, 2)
        return None

    def finalizar(self, status: int):
        self.fim = time.perf_counter()
        self.status_http = status

    def para_dict(self) -> Dict[str, Any]:
        return {
            "request_id":  self.request_id,
            "metodo":      self.metodo,
            "url":         self.url,
            "status_http": self.status_http,
            "duracao_ms":  self.duracao_ms,
            "tentativas":  self.tentativas,
            "protocolo":   self.protocolo,
            "erro":        self.erro,
        }


class QualityController:
    """
    Controle de Qualidade de Integração.

    Responsabilidades:
      - Medir latência de cada requisição
      - Registrar versões de protocolo e SDK
      - Acumular histórico de chamadas
      - Detectar degradações (SLA)
      - Gerar relatório de qualidade
    """

    SLA_UPLOAD_MS   = 5_000
    SLA_PROCESSO_MS = 2_000
    SLA_RESULTADO_MS= 3_000

    def __init__(self):
        self._historico: List[MetricaRequisicao] = []
        self._erros: List[Dict[str, Any]] = []
        logger.info("QualityController inicializado. SDK v%s | API %s",
                    SDK_VERSION, API_VERSION)

    def iniciar_req(self, metodo: str, url: str) -> MetricaRequisicao:
        rid = str(uuid.uuid4())
        m = MetricaRequisicao(request_id=rid, metodo=metodo, url=url)
        logger.debug("[QC] Iniciando %s %s | RID=%s", metodo, url, rid)
        return m

    def finalizar_req(self, metrica: MetricaRequisicao, status: int):
        metrica.finalizar(status)
        self._historico.append(metrica)
        nivel = "INFO" if status < 400 else "WARNING"
        getattr(logger, nivel.lower())(
            "[QC] %s %s → %d em %.2f ms (tentativas=%d)",
            metrica.metodo, metrica.url,
            status, metrica.duracao_ms, metrica.tentativas,
        )
        self._verificar_sla(metrica)

    def registrar_erro(self, metrica: MetricaRequisicao, exc: Exception):
        metrica.erro = str(exc)
        metrica.fim  = time.perf_counter()
        self._historico.append(metrica)
        self._erros.append({**metrica.para_dict(), "excecao": type(exc).__name__})
        logger.error("[QC] ERRO em %s %s | %s: %s",
                     metrica.metodo, metrica.url,
                     type(exc).__name__, exc)

    def _verificar_sla(self, m: MetricaRequisicao):
        sla = None
        if "/upload"    in m.url: sla = self.SLA_UPLOAD_MS
        elif "/processo" in m.url: sla = self.SLA_PROCESSO_MS
        elif "/resultado" in m.url: sla = self.SLA_RESULTADO_MS

        if sla and m.duracao_ms and m.duracao_ms > sla:
            logger.warning("[QC] ⚠ SLA VIOLADO! %.2f ms > %d ms para %s",
                           m.duracao_ms, sla, m.url)

    def relatorio(self) -> Dict[str, Any]:
        total = len(self._historico)
        sucesso = sum(1 for m in self._historico if m.status_http and m.status_http < 400)
        duracoes = [m.duracao_ms for m in self._historico if m.duracao_ms]
        return {
            "sdk_version":      SDK_VERSION,
            "api_version":      API_VERSION,
            "protocolo":        "HTTPS/REST",
            "total_requisicoes": total,
            "sucesso":          sucesso,
            "falhas":           total - sucesso,
            "taxa_sucesso_pct": round(sucesso / total * 100, 1) if total else 0,
            "latencia_media_ms": round(sum(duracoes) / len(duracoes), 2) if duracoes else 0,
            "latencia_max_ms":  max(duracoes, default=0),
            "latencia_min_ms":  min(duracoes, default=0),
            "total_erros":      len(self._erros),
            "historico":        [m.para_dict() for m in self._historico],
        }


# ══════════════════════════════════════════════
# CAMADA DE TRANSPORTE — HTTP com retry
# ══════════════════════════════════════════════
def _criar_sessao_http() -> requests.Session:
    """
    Cria sessão HTTP com:
      - Retry automático (3x) em falhas de rede (5xx, timeout)
      - Backoff exponencial
      - TLS verificado
    """
    sessao = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    sessao.mount("https://", adapter)
    sessao.mount("http://",  adapter)
    return sessao


# ══════════════════════════════════════════════
# CAMADA DE SERVIÇOS — AsisClient
# ══════════════════════════════════════════════
class AsisClient:
    """
    Cliente HTTP de baixo nível para a ASIS API.

    Responsabilidades:
      - Executar as chamadas HTTP (upload, processo, resultado)
      - Injetar autenticação (account-key, app-key, JWT Bearer)
      - Instrumentar todas as chamadas no QualityController
      - Tratar e mapear erros HTTP em exceções tipadas
    """

    def __init__(
        self,
        credenciais: CredenciaisAsis,
        ambiente: str = AMBIENTE_STG,
        qc: Optional[QualityController] = None,
    ):
        self._auth    = JwtAuth(credenciais)
        self._urls    = BASE_URLS[ambiente]
        self._sessao  = _criar_sessao_http()
        self._qc      = qc or QualityController()
        self.ambiente = ambiente
        logger.info("AsisClient pronto. Ambiente: %s", ambiente)

    # ── Métodos internos ──────────────────────
    def _req(
        self,
        metodo: str,
        servico: str,
        path: str,
        timeout: int = TIMEOUT_DEFAULT,
        **kwargs,
    ) -> requests.Response:
        url = f"{self._urls[servico]}/{path}"
        headers = self._auth.headers_autenticados()

        # Mescla headers extras sem sobrescrever autenticação
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        metrica = self._qc.iniciar_req(metodo, url)
        try:
            resp = self._sessao.request(
                metodo, url, headers=headers, timeout=timeout, **kwargs
            )
            self._qc.finalizar_req(metrica, resp.status_code)
            self._tratar_erro_http(resp, metrica)
            return resp
        except requests.Timeout as exc:
            self._qc.registrar_erro(metrica, exc)
            raise AsisTimeoutError(
                f"Timeout ({timeout}s) em {metodo} {url}", codigo=408
            ) from exc
        except requests.ConnectionError as exc:
            self._qc.registrar_erro(metrica, exc)
            raise AsisBaseError(f"Erro de conexão: {exc}", codigo=503) from exc

    def _tratar_erro_http(self, resp: requests.Response, m: MetricaRequisicao):
        if resp.status_code == 401:
            raise AsisAuthError("Não autorizado. Verifique account-key, app-key e JWT.",
                                codigo=401, detalhes=resp.text)
        if resp.status_code == 404:
            raise AsisBaseError(f"Recurso não encontrado: {m.url}", codigo=404)
        if resp.status_code == 413:
            raise AsisUploadError("Arquivo excede o tamanho permitido.", codigo=413)
        if resp.status_code >= 500:
            raise AsisBaseError(f"Erro interno da API ASIS ({resp.status_code})",
                                codigo=resp.status_code, detalhes=resp.text)

    # ── Endpoints públicos ────────────────────
    def upload_arquivo(self, caminho_arquivo: str) -> Dict[str, Any]:
        """
        POST /api/v1/upload
        Envia um arquivo SPED e retorna o ID do processo criado.
        """
        caminho = Path(caminho_arquivo)
        if not caminho.exists():
            raise AsisArquivoError(f"Arquivo não encontrado: {caminho_arquivo}")
        if caminho.stat().st_size == 0:
            raise AsisArquivoError("Arquivo está vazio.")

        logger.info("Upload iniciado: %s (%.1f KB)",
                    caminho.name, caminho.stat().st_size / 1024)

        # Para upload multipart, removemos Content-Type (requests define o boundary)
        headers_upload = {
            "account-key":   self._auth._cred.account_key,
            "app-key":       self._auth._cred.app_key,
            "Authorization": f"Bearer {self._auth.obter_token()}",
            "X-SDK-Version": SDK_VERSION,
        }

        url = f"{self._urls['upload']}/api/{API_VERSION}/upload"
        metrica = self._qc.iniciar_req("POST", url)
        try:
            with open(caminho, "rb") as arq:
                resp = self._sessao.post(
                    url,
                    headers=headers_upload,
                    files={"file": (caminho.name, arq, "text/plain")},
                    timeout=TIMEOUT_UPLOAD,
                )
            self._qc.finalizar_req(metrica, resp.status_code)
            self._tratar_erro_http(resp, metrica)
        except requests.Timeout as exc:
            self._qc.registrar_erro(metrica, exc)
            raise AsisTimeoutError(f"Timeout no upload ({TIMEOUT_UPLOAD}s)", codigo=408) from exc

        dados = resp.json()
        processos = dados.get("processos", [])
        if not processos:
            raise AsisUploadError("Resposta de upload sem processos.", detalhes=dados)

        processo = processos[0]
        logger.info("Upload concluído. Processo ID=%s | Arquivo ID=%s",
                    processo["id"], processo["arquivoId"])
        return processo

    def upload_base64(self, nome_arquivo: str, conteudo_b64: str) -> Dict[str, Any]:
        """
        POST /api/v1/upload/base64
        Envia arquivo em Base64 (recomendado apenas para arquivos ≤ 1 MB).
        """
        logger.info("Upload Base64 iniciado: %s", nome_arquivo)
        resp = self._req(
            "POST",
            "upload",
            f"api/{API_VERSION}/upload/base64",
            params={"nome": nome_arquivo},
            headers={"Content-Type": "application/octet-stream"},
            data=conteudo_b64,
            timeout=TIMEOUT_UPLOAD,
        )
        dados = resp.json()
        processo = dados.get("processos", [{}])[0]
        logger.info("Upload Base64 concluído. Processo ID=%s", processo.get("id"))
        return processo

    def consultar_processo(self, processo_id: int) -> Dict[str, Any]:
        """
        GET /api/v1/processo/{id}
        Consulta o estado atual de um processo.
        """
        resp = self._req(
            "GET",
            "core",
            f"api/{API_VERSION}/processo/{processo_id}",
            timeout=TIMEOUT_POLL,
        )
        return resp.json()

    def consultar_resultados(self, processo_id: int) -> List[Dict[str, Any]]:
        """
        GET /api/v1/resultado/processo/{id}
        Retorna os resultados sintéticos de um processo concluído.
        """
        resp = self._req(
            "GET",
            "result",
            f"api/{API_VERSION}/resultado/processo/{processo_id}",
            timeout=TIMEOUT_DEFAULT,
        )
        return resp.json()

    def consultar_resultado_analitico(
        self, processo_id: int, auditoria_id: int
    ) -> Dict[str, Any]:
        """
        GET /api/v1/resultado/processo/{id}/auditoria/{auditoriaId}
        Retorna os itens analíticos de uma auditoria específica.
        """
        resp = self._req(
            "GET",
            "result",
            f"api/{API_VERSION}/resultado/processo/{processo_id}/auditoria/{auditoria_id}",
            timeout=TIMEOUT_DEFAULT,
        )
        return resp.json()

    @property
    def quality_controller(self) -> QualityController:
        return self._qc


# ══════════════════════════════════════════════
# CAMADA DE ORQUESTRAÇÃO — Fluxo Completo
# ══════════════════════════════════════════════
@dataclass
class ResultadoFluxo:
    """Resultado consolidado do fluxo completo de integração."""
    processo_id: int
    arquivo_id: int
    nome_arquivo: str
    status_final: StatusProcesso
    resultados_sinteticos: List[Dict[str, Any]] = field(default_factory=list)
    resultados_analiticos: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    duracao_total_seg: float = 0.0
    relatorio_qualidade: Dict[str, Any] = field(default_factory=dict)
    timestamp_inicio: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def resumo(self) -> str:
        linhas = [
            "=" * 60,
            "  RESULTADO DO FLUXO ASIS API",
            "=" * 60,
            f"  Processo ID   : {self.processo_id}",
            f"  Arquivo ID    : {self.arquivo_id}",
            f"  Nome          : {self.nome_arquivo}",
            f"  Status Final  : {self.status_final.name} ({self.status_final.value})",
            f"  Duração Total : {self.duracao_total_seg:.2f}s",
            f"  Auditorias    : {len(self.resultados_sinteticos)}",
            f"  Analíticos    : {len(self.resultados_analiticos)}",
            "-" * 60,
            "  QUALIDADE:",
            f"  Requisições   : {self.relatorio_qualidade.get('total_requisicoes', 0)}",
            f"  Sucesso       : {self.relatorio_qualidade.get('taxa_sucesso_pct', 0)}%",
            f"  Latência Média: {self.relatorio_qualidade.get('latencia_media_ms', 0)} ms",
            "=" * 60,
        ]
        return "\n".join(linhas)


class AsisFluxoIntegracao:
    """
    Orquestrador do Fluxo Completo de Integração ASIS API.

    Fluxo:
      [1] Verificação de credenciais / JWT
      [2] Upload do arquivo SPED
      [3] Polling do processo (aguarda conclusão)
      [4] Consulta dos resultados sintéticos
      [5] Consulta dos resultados analíticos (por auditoria)
      [6] Geração do relatório de qualidade
    """

    def __init__(self, cliente: AsisClient):
        self._cli = cliente
        logger.info("AsisFluxoIntegracao pronto.")

    # ── ETAPA 1: Verificar autenticação ──────
    def verificar_autenticacao(self) -> bool:
        """
        Verifica se as credenciais e o JWT estão válidos
        antes de iniciar o fluxo principal.
        """
        logger.info("► ETAPA 1: Verificando autenticação JWT...")
        try:
            token_str = self._cli._auth.obter_token()
            payload   = self._cli._auth.validar_token(token_str)
            logger.info(
                "  ✓ JWT válido. JTI=%s | Expira em: %s",
                payload.get("jti"),
                datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
            )
            return True
        except AsisAuthError as exc:
            logger.error("  ✗ Falha de autenticação: %s", exc)
            raise

    # ── ETAPA 2: Upload ───────────────────────
    def _etapa_upload(self, caminho_arquivo: str) -> Dict[str, Any]:
        logger.info("► ETAPA 2: Upload do arquivo...")
        processo = self._cli.upload_arquivo(caminho_arquivo)
        logger.info("  ✓ Processo criado. ID=%s", processo["id"])
        return processo

    # ── ETAPA 3: Polling do processo ─────────
    def _etapa_aguardar_processo(self, processo_id: int) -> Dict[str, Any]:
        logger.info("► ETAPA 3: Aguardando conclusão do processo %s...", processo_id)
        intervalo  = POLL_INTERVALO_INICIAL
        tentativas = 0

        while tentativas < POLL_MAX_TENTATIVAS:
            tentativas += 1
            dados  = self._cli.consultar_processo(processo_id)
            status = StatusProcesso(dados.get("status", 0))
            logger.info(
                "  [%02d/%02d] Status: %s (%d) | Aguardando %ss...",
                tentativas, POLL_MAX_TENTATIVAS,
                status.name, status.value, intervalo,
            )

            if status == StatusProcesso.CONCLUIDO:
                logger.info("  ✓ Processo concluído com sucesso.")
                return dados

            if status == StatusProcesso.ERRO:
                raise AsisProcessoError(
                    f"Processo {processo_id} encerrou com ERRO.",
                    codigo=500, detalhes=dados,
                )

            if status == StatusProcesso.CANCELADO:
                raise AsisProcessoError(
                    f"Processo {processo_id} foi CANCELADO.",
                    codigo=204, detalhes=dados,
                )

            time.sleep(intervalo)
            intervalo = min(intervalo * 1.5, POLL_INTERVALO_MAX)

        raise AsisTimeoutError(
            f"Processo {processo_id} não concluiu em "
            f"{POLL_MAX_TENTATIVAS} tentativas.",
            codigo=408,
        )

    # ── ETAPA 4: Resultados Sintéticos ────────
    def _etapa_resultados_sinteticos(self, processo_id: int) -> List[Dict[str, Any]]:
        logger.info("► ETAPA 4: Consultando resultados sintéticos...")
        resultados = self._cli.consultar_resultados(processo_id)
        logger.info("  ✓ %d resultado(s) sintético(s) recebidos.", len(resultados))
        for r in resultados:
            logger.info(
                "    • [%s] %s | Qtde: %d",
                r.get("diagnostico"), r.get("nome"), r.get("qtdeResultados", 0),
            )
        return resultados

    # ── ETAPA 5: Resultados Analíticos ────────
    def _etapa_resultados_analiticos(
        self,
        processo_id: int,
        resultados_sinteticos: List[Dict[str, Any]],
        max_analiticos: int = 3,
    ) -> Dict[int, Dict[str, Any]]:
        logger.info(
            "► ETAPA 5: Consultando resultados analíticos "
            "(máx. %d auditorias)...", max_analiticos
        )
        analiticos: Dict[int, Dict[str, Any]] = {}
        for r in resultados_sinteticos[:max_analiticos]:
            auditoria_id = r.get("auditoriaId")
            if not auditoria_id:
                continue
            try:
                dados = self._cli.consultar_resultado_analitico(
                    processo_id, auditoria_id
                )
                qtde_itens = len(dados.get("dados", []))
                analiticos[auditoria_id] = dados
                logger.info(
                    "  ✓ Auditoria %d: %d item(ns) analítico(s).",
                    auditoria_id, qtde_itens,
                )
            except AsisBaseError as exc:
                logger.warning(
                    "  ⚠ Falha ao buscar analítico para auditoria %d: %s",
                    auditoria_id, exc,
                )
        return analiticos

    # ── Fluxo Principal ───────────────────────
    def executar(
        self,
        caminho_arquivo: str,
        max_analiticos: int = 3,
    ) -> ResultadoFluxo:
        """
        Executa o fluxo completo de integração ASIS.

        Args:
            caminho_arquivo: Caminho local do arquivo SPED a auditar.
            max_analiticos:  Máximo de auditorias para consulta analítica.

        Returns:
            ResultadoFluxo com todos os dados e métricas de qualidade.
        """
        inicio = time.perf_counter()
        logger.info("═" * 60)
        logger.info("  INICIANDO FLUXO DE INTEGRAÇÃO ASIS API")
        logger.info("  Ambiente : %s", self._cli.ambiente)
        logger.info("  SDK      : v%s | API: %s", SDK_VERSION, API_VERSION)
        logger.info("═" * 60)

        # ETAPA 1 — Autenticação
        self.verificar_autenticacao()

        # ETAPA 2 — Upload
        processo_info = self._etapa_upload(caminho_arquivo)
        processo_id   = processo_info["id"]
        arquivo_id    = processo_info["arquivoId"]
        nome_arquivo  = processo_info.get("nome", Path(caminho_arquivo).name)

        # ETAPA 3 — Aguardar conclusão
        processo_final = self._etapa_aguardar_processo(processo_id)
        status_final   = StatusProcesso(processo_final.get("status", 201))

        # ETAPA 4 — Resultados Sintéticos
        sinteticos = self._etapa_resultados_sinteticos(processo_id)

        # ETAPA 5 — Resultados Analíticos
        analiticos = self._etapa_resultados_analiticos(
            processo_id, sinteticos, max_analiticos
        )

        # ETAPA 6 — Relatório de Qualidade
        logger.info("► ETAPA 6: Gerando relatório de qualidade...")
        duracao = time.perf_counter() - inicio
        relatorio = self._cli.quality_controller.relatorio()

        resultado = ResultadoFluxo(
            processo_id=processo_id,
            arquivo_id=arquivo_id,
            nome_arquivo=nome_arquivo,
            status_final=status_final,
            resultados_sinteticos=sinteticos,
            resultados_analiticos=analiticos,
            duracao_total_seg=round(duracao, 2),
            relatorio_qualidade=relatorio,
        )

        logger.info("  ✓ Fluxo concluído em %.2fs", duracao)
        logger.info(resultado.resumo())
        return resultado
