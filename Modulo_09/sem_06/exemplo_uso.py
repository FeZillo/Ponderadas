"""
======================================================================
ASIS API — Exemplo de Uso do Fluxo Completo de Integração
======================================================================
Demonstra como usar o SDK em um cenário real, com configuração
de credenciais, execução do fluxo e exibição do relatório de qualidade.

Execute:
    python exemplo_uso.py
"""

import json
import logging
import os
import tempfile

from asis_client import (
    CredenciaisAsis,
    AsisClient,
    AsisFluxoIntegracao,
    AMBIENTE_STG,
    AsisBaseError,
    AsisAuthError,
    AsisTimeoutError,
    AsisProcessoError,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")


def criar_arquivo_sped_demo() -> str:
    """Cria um arquivo SPED fictício para demonstração."""
    conteudo = (
        "|0000|015|0|01012018|31012018|EMPRESA DEMO LTDA|12345678000100|"
        "SP|1234567|1234|1|D|1|\n"
        "|0001|0|\n"
        "|0200|PROD001|PRODUTO DEMONSTRACAO|UN|12345678||60|0|\n"
        "|0990|3|\n"
        "|9999|5|\n"
    )
    arq = tempfile.NamedTemporaryFile(
        suffix=".txt",
        delete=False,
        mode="w",
        encoding="latin-1",
        prefix="sped_demo_",
    )
    arq.write(conteudo)
    arq.close()
    return arq.name


def main():
    print("\n" + "═" * 60)
    print("   ASIS API — Demonstração do Fluxo de Integração")
    print("═" * 60 + "\n")

    # ── 1. Configurar credenciais ─────────────────────────────
    # Em produção, use variáveis de ambiente ou cofre de segredos
    credenciais = CredenciaisAsis(
        account_key=os.getenv(
            "ASIS_ACCOUNT_KEY",
            "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e",
        ),
        app_key=os.getenv(
            "ASIS_APP_KEY",
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb",
        ),
        jwt_secret=os.getenv("ASIS_JWT_SECRET", "segredo-local-dev"),
        jwt_expiracao_min=60,
    )

    # ── 2. Criar cliente e fluxo ──────────────────────────────
    cliente = AsisClient(credenciais, ambiente=AMBIENTE_STG)
    fluxo   = AsisFluxoIntegracao(cliente)

    # ── 3. Preparar arquivo SPED ──────────────────────────────
    caminho_arquivo = criar_arquivo_sped_demo()
    print(f"Arquivo SPED criado: {caminho_arquivo}\n")

    try:
        # ── 4. Executar fluxo completo ────────────────────────
        resultado = fluxo.executar(
            caminho_arquivo=caminho_arquivo,
            max_analiticos=3,
        )

        # ── 5. Exibir resultados ──────────────────────────────
        print(resultado.resumo())

        print("\n--- Resultados Sintéticos ---")
        for r in resultado.resultados_sinteticos:
            print(f"  [{r['diagnostico']}] {r['nome']} | Qtde: {r['qtdeResultados']}")

        print("\n--- Relatório de Qualidade (JSON) ---")
        print(json.dumps(resultado.relatorio_qualidade, indent=2, ensure_ascii=False))

    # ── 6. Tratamento de exceções ──────────────────────────────
    except AsisAuthError as exc:
        print(f"\n[ERRO DE AUTENTICAÇÃO] {exc}")
        print("  → Verifique account-key, app-key e jwt_secret.")

    except AsisTimeoutError as exc:
        print(f"\n[TIMEOUT] {exc}")
        print("  → Verifique conectividade e tente novamente.")

    except AsisProcessoError as exc:
        print(f"\n[ERRO NO PROCESSO] {exc}")
        print(f"  → Detalhes: {exc.detalhes}")

    except AsisBaseError as exc:
        print(f"\n[ERRO ASIS API] {exc} (código={exc.codigo})")

    finally:
        # Limpeza do arquivo temporário
        if os.path.exists(caminho_arquivo):
            os.remove(caminho_arquivo)
        print("\nArquivo temporário removido.")
        print("\nRelório de qualidade completo disponível no objeto `resultado`.\n")


if __name__ == "__main__":
    main()
