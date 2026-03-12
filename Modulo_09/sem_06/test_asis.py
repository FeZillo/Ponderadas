"""
======================================================================
ASIS API — Suite de Testes de Qualidade de Integração
======================================================================
Testa todas as camadas do cliente de integração:
  - Autenticação JWT (geração, validação, expiração, renovação)
  - Upload de arquivos (sucesso, arquivo ausente, timeout)
  - Polling de processo (concluído, erro, timeout)
  - Resultados sintéticos e analíticos
  - Controle de qualidade (latência, SLA, relatório)
  - Tratamento de exceções tipadas

Protocolo  : HTTPS (mockado via unittest.mock)
Versão API : v1
Versão SDK : 1.0.0
"""

import base64
import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

from asis_client import (
    SDK_VERSION, API_VERSION,
    AMBIENTE_STG, StatusProcesso,
    CredenciaisAsis, JwtAuth, TokenJWT,
    QualityController, MetricaRequisicao,
    AsisClient, AsisFluxoIntegracao, ResultadoFluxo,
    AsisAuthError, AsisUploadError, AsisTimeoutError,
    AsisProcessoError, AsisArquivoError, AsisBaseError,
)


# ──────────────────────────────────────────────
# Fixtures compartilhadas
# ──────────────────────────────────────────────
CRED_TESTE = CredenciaisAsis(
    account_key="4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e",
    app_key="6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb",
    jwt_secret="segredo-super-secreto-para-testes",
    jwt_expiracao_min=5,
)

PROCESSO_RESP = {
    "id": 22362,
    "nome": "sped_fiscal.txt",
    "dataHoraCriacao": "06-06-2018 12:34:46",
    "arquivoId": 22740,
}

PROCESSO_STATUS_CONCLUIDO = {
    "id": 22362,
    "nome": "sped_fiscal.txt",
    "status": 201,
    "arquivoId": 22740,
    "dataHoraCriacao": "06-06-2018 12:34:46",
    "dataHoraInicio":  "06-06-2018 12:34:47",
    "dataHoraFim":     "06-06-2018 12:35:11",
}

RESULTADO_SINTETICO = [
    {
        "diagnostico": "R",
        "codigo": 538,
        "ementa": "Ausência do COD_CTA Transporte",
        "auditoriaId": 110,
        "nivel": 1,
        "nome": "538 Ausência do COD_CTA Transporte",
        "qtdeResultados": 355,
        "resultadoId": 5541810,
    },
    {
        "diagnostico": "Y",
        "codigo": 2396,
        "ementa": "Ausência de escrituração do Registro D197",
        "auditoriaId": 315,
        "nivel": 1,
        "nome": "2396 Alerta Ausência D197",
        "qtdeResultados": 1,
        "resultadoId": 5541861,
    },
]

RESULTADO_ANALITICO = {
    "cabecalho": ["REG", "COD_CTA", "NUM_DOC", "DT_ENTR_SAÍDA", "VL_DOC"],
    "dados": [
        ["D100", "null", "4034", "2018-02-20", "360.00"],
        ["D100", "null", "3975", "2018-02-16", "300.00"],
    ],
}


def _mock_resp(status: int, payload: any) -> MagicMock:
    """Cria um mock de requests.Response."""
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.text = json.dumps(payload)
    return r


# ══════════════════════════════════════════════
# 1. Testes de Autenticação JWT
# ══════════════════════════════════════════════
class TestJwtAuth(unittest.TestCase):

    def setUp(self):
        self.auth = JwtAuth(CRED_TESTE)

    def test_gerar_token_retorna_string(self):
        token = self.auth.obter_token()
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 20, "Token JWT deve ter mais de 20 chars")

    def test_token_valido_nao_e_regenerado(self):
        tok1 = self.auth.obter_token()
        tok2 = self.auth.obter_token()
        self.assertEqual(tok1, tok2, "Token válido não deve ser regenerado")

    def test_validar_token_proprio(self):
        token = self.auth.obter_token()
        payload = self.auth.validar_token(token)
        self.assertEqual(payload["account_key"], CRED_TESTE.account_key)
        self.assertEqual(payload["app_key"],     CRED_TESTE.app_key)
        self.assertEqual(payload["sdk_version"], SDK_VERSION)
        self.assertEqual(payload["api_version"], API_VERSION)

    def test_token_expirado_lanca_erro(self):
        import jwt as pyjwt
        payload_expirado = {
            "iss": "asis-sdk",
            "sub": CRED_TESTE.account_key,
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
            "jti": "expirado-id",
            "account_key": CRED_TESTE.account_key,
            "app_key":     CRED_TESTE.app_key,
            "sdk_version": SDK_VERSION,
            "api_version": API_VERSION,
        }
        token_exp = pyjwt.encode(payload_expirado, CRED_TESTE.jwt_secret, algorithm="HS256")
        with self.assertRaises(AsisAuthError) as ctx:
            self.auth.validar_token(token_exp)
        self.assertEqual(ctx.exception.codigo, 401)
        self.assertIn("expirado", str(ctx.exception).lower())

    def test_token_invalido_lanca_erro(self):
        with self.assertRaises(AsisAuthError) as ctx:
            self.auth.validar_token("token.invalido.assinatura")
        self.assertEqual(ctx.exception.codigo, 401)

    def test_headers_autenticados_possuem_campos_obrigatorios(self):
        headers = self.auth.headers_autenticados()
        self.assertIn("account-key",   headers)
        self.assertIn("app-key",       headers)
        self.assertIn("Authorization", headers)
        self.assertTrue(headers["Authorization"].startswith("Bearer "))
        self.assertEqual(headers["X-SDK-Version"], SDK_VERSION)
        self.assertEqual(headers["X-API-Version"], API_VERSION)
        self.assertIn("X-Request-ID", headers)  # UUID único por req

    def test_renovacao_automatica_token_expirado(self):
        """Token marcado como expirado deve ser substituído ao obter_token()."""
        # Força token "quase expirado" (margem 30s, expira em 10s)
        token_real = self.auth.obter_token()
        self.auth._token.expira_em = datetime.now(timezone.utc) + timedelta(seconds=10)
        novo_token = self.auth.obter_token()
        self.assertNotEqual(token_real, novo_token, "Token deve ter sido renovado")

    def test_token_possui_jti_unico(self):
        """Cada token gerado deve ter um JTI diferente."""
        self.auth._token = None
        tok1_str = self.auth.obter_token()
        self.auth._token = None
        tok2_str = self.auth.obter_token()
        payload1 = self.auth.validar_token(tok1_str)
        payload2 = self.auth.validar_token(tok2_str)
        self.assertNotEqual(payload1["jti"], payload2["jti"])


# ══════════════════════════════════════════════
# 2. Testes de Controle de Qualidade
# ══════════════════════════════════════════════
class TestQualityController(unittest.TestCase):

    def setUp(self):
        self.qc = QualityController()

    def test_metrica_mede_duracao(self):
        m = self.qc.iniciar_req("GET", "https://exemplo.com/api/v1/processo/1")
        time.sleep(0.05)
        self.qc.finalizar_req(m, 200)
        self.assertIsNotNone(m.duracao_ms)
        self.assertGreater(m.duracao_ms, 40, "Deve medir ≥ 40ms para sleep de 50ms")

    def test_relatorio_acumula_requisicoes(self):
        for i in range(3):
            m = self.qc.iniciar_req("GET", f"https://x.com/{i}")
            self.qc.finalizar_req(m, 200)
        r = self.qc.relatorio()
        self.assertEqual(r["total_requisicoes"], 3)
        self.assertEqual(r["sucesso"], 3)
        self.assertEqual(r["falhas"], 0)
        self.assertEqual(r["taxa_sucesso_pct"], 100.0)

    def test_relatorio_conta_falhas(self):
        m_ok  = self.qc.iniciar_req("GET", "https://x.com/ok")
        self.qc.finalizar_req(m_ok, 200)
        m_err = self.qc.iniciar_req("GET", "https://x.com/err")
        self.qc.finalizar_req(m_err, 500)
        r = self.qc.relatorio()
        self.assertEqual(r["falhas"], 1)
        self.assertEqual(r["taxa_sucesso_pct"], 50.0)

    def test_relatorio_inclui_versoes(self):
        r = self.qc.relatorio()
        self.assertEqual(r["sdk_version"], SDK_VERSION)
        self.assertEqual(r["api_version"], API_VERSION)
        self.assertEqual(r["protocolo"],   "HTTPS/REST")

    def test_registrar_erro_inclui_excecao(self):
        m = self.qc.iniciar_req("POST", "https://x.com/upload")
        exc = ConnectionError("Sem conexão")
        self.qc.registrar_erro(m, exc)
        r = self.qc.relatorio()
        self.assertEqual(r["total_erros"], 1)
        self.assertIn("excecao", self.qc._erros[0])

    def test_latencia_media_calculada(self):
        for _ in range(5):
            m = self.qc.iniciar_req("GET", "https://x.com")
            time.sleep(0.01)
            self.qc.finalizar_req(m, 200)
        r = self.qc.relatorio()
        self.assertGreater(r["latencia_media_ms"], 0)
        self.assertGreaterEqual(r["latencia_max_ms"], r["latencia_media_ms"])


# ══════════════════════════════════════════════
# 3. Testes do AsisClient (HTTP mockado)
# ══════════════════════════════════════════════
class TestAsisClient(unittest.TestCase):

    def _cliente(self) -> AsisClient:
        return AsisClient(CRED_TESTE, ambiente=AMBIENTE_STG)

    @patch("asis_client.requests.Session.request")
    def test_consultar_processo_sucesso(self, mock_req):
        mock_req.return_value = _mock_resp(200, PROCESSO_STATUS_CONCLUIDO)
        cli = self._cliente()
        dados = cli.consultar_processo(22362)
        self.assertEqual(dados["id"], 22362)
        self.assertEqual(dados["status"], 201)
        mock_req.assert_called_once()

    @patch("asis_client.requests.Session.request")
    def test_consultar_resultados_sinteticos(self, mock_req):
        mock_req.return_value = _mock_resp(200, RESULTADO_SINTETICO)
        cli = self._cliente()
        res = cli.consultar_resultados(22362)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["auditoriaId"], 110)

    @patch("asis_client.requests.Session.request")
    def test_consultar_resultado_analitico(self, mock_req):
        mock_req.return_value = _mock_resp(200, RESULTADO_ANALITICO)
        cli = self._cliente()
        res = cli.consultar_resultado_analitico(22362, 110)
        self.assertIn("cabecalho", res)
        self.assertIn("dados", res)
        self.assertEqual(len(res["dados"]), 2)

    @patch("asis_client.requests.Session.request")
    def test_erro_401_lanca_auth_error(self, mock_req):
        mock_req.return_value = _mock_resp(401, {"erro": "Não autorizado"})
        cli = self._cliente()
        with self.assertRaises(AsisAuthError) as ctx:
            cli.consultar_processo(99999)
        self.assertEqual(ctx.exception.codigo, 401)

    @patch("asis_client.requests.Session.request")
    def test_erro_500_lanca_base_error(self, mock_req):
        mock_req.return_value = _mock_resp(500, {"erro": "Servidor indisponível"})
        cli = self._cliente()
        with self.assertRaises(AsisBaseError) as ctx:
            cli.consultar_processo(1)
        self.assertGreaterEqual(ctx.exception.codigo, 500)

    @patch("asis_client.requests.Session.request")
    def test_timeout_lanca_timeout_error(self, mock_req):
        import requests as req_lib
        mock_req.side_effect = req_lib.Timeout("Timeout simulado")
        cli = self._cliente()
        with self.assertRaises(AsisTimeoutError) as ctx:
            cli.consultar_processo(1)
        self.assertEqual(ctx.exception.codigo, 408)

    def test_upload_arquivo_ausente_lanca_erro(self):
        cli = self._cliente()
        with self.assertRaises(AsisArquivoError):
            cli.upload_arquivo("/caminho/inexistente/arquivo.txt")

    def test_upload_arquivo_vazio_lanca_erro(self):
        cli = self._cliente()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            caminho = f.name
        with self.assertRaises(AsisArquivoError):
            cli.upload_arquivo(caminho)

    @patch("asis_client.requests.Session.post")
    def test_upload_arquivo_sucesso(self, mock_post):
        mock_post.return_value = _mock_resp(200, {"processos": [PROCESSO_RESP]})
        cli = self._cliente()
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w"
        ) as f:
            f.write("|0000|...")
            caminho = f.name
        processo = cli.upload_arquivo(caminho)
        self.assertEqual(processo["id"], 22362)
        self.assertEqual(processo["arquivoId"], 22740)


# ══════════════════════════════════════════════
# 4. Testes do Fluxo Completo de Integração
# ══════════════════════════════════════════════
class TestAsisFluxoIntegracao(unittest.TestCase):

    def _criar_fluxo_e_arquivo(self):
        qc  = QualityController()
        cli = AsisClient(CRED_TESTE, ambiente=AMBIENTE_STG, qc=qc)
        fluxo = AsisFluxoIntegracao(cli)
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False, mode="w"
        ) as f:
            f.write("|0000|EFD|SPED TESTE|")
            caminho = f.name
        return fluxo, cli, caminho

    def test_verificar_autenticacao_retorna_true(self):
        fluxo, _, _ = self._criar_fluxo_e_arquivo()
        self.assertTrue(fluxo.verificar_autenticacao())

    @patch("asis_client.requests.Session.post")
    @patch("asis_client.requests.Session.request")
    def test_fluxo_completo_sucesso(self, mock_req, mock_post):
        """Simula o fluxo completo: upload → polling → sintético → analítico."""

        # Upload retorna processo
        mock_post.return_value = _mock_resp(200, {"processos": [PROCESSO_RESP]})

        # Sequência de chamadas GET:
        # 1a → processo em processamento
        # 2a → processo concluído
        # 3a → resultados sintéticos
        # 4a → resultado analítico auditoria 110
        # 5a → resultado analítico auditoria 315
        mock_req.side_effect = [
            _mock_resp(200, {**PROCESSO_STATUS_CONCLUIDO, "status": 150}),  # processando
            _mock_resp(200, PROCESSO_STATUS_CONCLUIDO),                      # concluído
            _mock_resp(200, RESULTADO_SINTETICO),                            # sintético
            _mock_resp(200, RESULTADO_ANALITICO),                            # analítico 110
            _mock_resp(200, RESULTADO_ANALITICO),                            # analítico 315
        ]

        fluxo, cli, caminho = self._criar_fluxo_e_arquivo()
        with patch("asis_client.POLL_INTERVALO_INICIAL", 0):
            resultado = fluxo.executar(caminho, max_analiticos=2)

        self.assertIsInstance(resultado, ResultadoFluxo)
        self.assertEqual(resultado.processo_id, 22362)
        self.assertEqual(resultado.status_final, StatusProcesso.CONCLUIDO)
        self.assertEqual(len(resultado.resultados_sinteticos), 2)
        self.assertEqual(len(resultado.resultados_analiticos), 2)
        self.assertGreaterEqual(resultado.duracao_total_seg, 0)

        # Verifica relatório de qualidade
        rel = resultado.relatorio_qualidade
        self.assertEqual(rel["sdk_version"], SDK_VERSION)
        self.assertGreater(rel["total_requisicoes"], 0)

    @patch("asis_client.requests.Session.request")
    @patch("asis_client.requests.Session.post")
    def test_processo_com_erro_lanca_excecao(self, mock_post, mock_req):
        mock_post.return_value = _mock_resp(200, {"processos": [PROCESSO_RESP]})
        mock_req.return_value  = _mock_resp(200, {**PROCESSO_STATUS_CONCLUIDO, "status": 500})

        fluxo, _, caminho = self._criar_fluxo_e_arquivo()
        with patch("asis_client.POLL_INTERVALO_INICIAL", 0):
            with self.assertRaises(AsisProcessoError) as ctx:
                fluxo.executar(caminho)
        self.assertEqual(ctx.exception.codigo, 500)

    @patch("asis_client.requests.Session.request")
    @patch("asis_client.requests.Session.post")
    @patch("asis_client.POLL_MAX_TENTATIVAS", 2)
    def test_polling_timeout_lanca_excecao(self, mock_post, mock_req):
        mock_post.return_value = _mock_resp(200, {"processos": [PROCESSO_RESP]})
        mock_req.return_value  = _mock_resp(200, {**PROCESSO_STATUS_CONCLUIDO, "status": 150})

        fluxo, _, caminho = self._criar_fluxo_e_arquivo()
        with patch("asis_client.POLL_INTERVALO_INICIAL", 0):
            with patch("asis_client.POLL_MAX_TENTATIVAS", 2):
                with self.assertRaises(AsisTimeoutError):
                    fluxo.executar(caminho)

    def test_resultado_fluxo_resumo_contem_campos(self):
        r = ResultadoFluxo(
            processo_id=1,
            arquivo_id=2,
            nome_arquivo="teste.txt",
            status_final=StatusProcesso.CONCLUIDO,
            duracao_total_seg=5.5,
            relatorio_qualidade={
                "total_requisicoes": 4,
                "taxa_sucesso_pct": 100.0,
                "latencia_media_ms": 120.5,
            },
        )
        resumo = r.resumo()
        self.assertIn("CONCLUIDO", resumo)
        self.assertIn("5.50s", resumo)
        self.assertIn("100.0%", resumo)


# ══════════════════════════════════════════════
# 5. Testes de Protocolo e Versionamento
# ══════════════════════════════════════════════
class TestProtocoloVersao(unittest.TestCase):

    def test_sdk_version_definida(self):
        self.assertEqual(SDK_VERSION, "1.0.0")

    def test_api_version_definida(self):
        self.assertEqual(API_VERSION, "v1")

    def test_headers_possuem_versao(self):
        auth = JwtAuth(CRED_TESTE)
        h = auth.headers_autenticados()
        self.assertEqual(h["X-SDK-Version"], SDK_VERSION)
        self.assertEqual(h["X-API-Version"], API_VERSION)

    def test_relatorio_qualidade_inclui_protocolo(self):
        qc = QualityController()
        r  = qc.relatorio()
        self.assertIn("protocolo", r)
        self.assertIn("HTTPS", r["protocolo"])

    def test_status_processo_enum_completo(self):
        """Todos os status esperados pela API ASIS devem estar mapeados."""
        esperados = {100, 150, 201, 500, 204}
        presentes = {s.value for s in StatusProcesso}
        self.assertEqual(esperados, presentes)

    def test_excecoes_possuem_timestamp(self):
        exc = AsisBaseError("Erro teste", codigo=999)
        self.assertIn("T", exc.timestamp)  # ISO format com T

    def test_excecoes_possuem_codigo(self):
        for cls, codigo in [
            (AsisAuthError, 401),
            (AsisTimeoutError, 408),
            (AsisProcessoError, 500),
        ]:
            exc = cls("Erro", codigo=codigo)
            self.assertEqual(exc.codigo, codigo)


# ──────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  ASIS API — Suite de Testes de Qualidade de Integração")
    print(f"  SDK v{SDK_VERSION} | API {API_VERSION}")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [
        TestJwtAuth,
        TestQualityController,
        TestAsisClient,
        TestAsisFluxoIntegracao,
        TestProtocoloVersao,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"  Total: {result.testsRun} | "
          f"OK: {result.testsRun - len(result.failures) - len(result.errors)} | "
          f"Falhas: {len(result.failures)} | "
          f"Erros: {len(result.errors)}")
    print("=" * 60)
