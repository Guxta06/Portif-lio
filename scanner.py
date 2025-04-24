import requests 

def salvar_relatorio(texto):
    with open("report.txt", "a", encoding="utf-8") as f:
        f.write(texto + "\n")


def escanear_varias_urls(arquivo):
    try:
        with open(arquivo, "r") as f:
            urls = [linha.strip() for linha in f.readlines() if linha.strip()]

        for url in urls:
            print("\n" + "="*50)
            print(f"[INÍCIO] Escaneando: {url}")
            salvar_relatorio("="*50)
            salvar_relatorio(f"[INÍCIO] Escaneando: {url}")

            verificar_headers(url)
            verificar_ssl(url)
            verificar_redirecionamento_https(url)

            salvar_relatorio("")  # linha em branco

    except FileNotFoundError:
        print(f"[ERRO] Arquivo {arquivo} não encontrado.")

def verificar_headers(url):
    print(f"\n[+] Verificando headers de segurança em: {url}\n")
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        cabecalhos_criticos = [
            'Content-Security-Policy',
            'strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        for h in cabecalhos_criticos:
            if h in headers:
                msg = f"[OK] {h}: {headers[h]}"
            else:
                msg = f"[ALERTA] {h} está ausente!"
            print(msg)
            salvar_relatorio(msg)

        for h in cabecalhos_criticos:
            if h in headers:
                print(f"[OK] {h}: {headers[h]}")
            else:
                print(f"[ALERTA] {h} não encontrado!")

    except Exception as e:
        print(f"[ERRO] Não foi possível acessar {url}: {e}")
        detectar_servidor(response)


import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def verificar_ssl(url):
    print(f"\n[+] Verificando certificado SSL de: {url}\n")

    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"[OK] Certificado SSL encontrado para {cert['subject'][0][0][1]}")
                salvar_relatorio(f"[OK] Certificado válido para: {cert['subject'][0][0][1]}")
                print(f"[INFO] Emitido por: {cert['issuer'][0][0][1]}")
                salvar_relatorio(f"[INFO] Emitido por: {cert['issuer'][0][0][1]}")

                validade = cert['notAfter']
                expira_em = datetime.strptime(validade, '%b %d %H:%M:%S %Y %Z')
                dias_restantes = (expira_em - datetime.utcnow()).days

                print(f"[INFO] Expira em: {expira_em}")

                if dias_restantes < 30:
                    print(f"[ALERTA] O certificado SSL expira em {dias_restantes} dias!")

    except Exception as e:
        print(f"[ERRO] Não foi possível acessar {url}: {e}")

def verificar_redirecionamento_https(url):
    print(f"\n[+] Verificando redirecionamento de HTTP para HTTPS...\n")
    parsed = urlparse(url)
    http_url = f"http://{parsed.hostname}"

    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        final_url = response.url
        if final_url.startswith("https://"):
            print(f"[OK] Redirecionamento de HTTP para HTTPS bem-sucedido: {final_url}")
        else:
            print(f"[ALERTA] Redirecionamento falhou. URL final: {final_url}")
    except Exception as e:
        print(f"[ERRO] Não foi possível acessar {http_url}: {e}")


def detectar_servidor(response):
    print("\n[+] Detectando tipo de servidor...\n")
    server = response.headers.get("Server")
    if server:
        print(f"[INFO] Servidor identificado: {server}")
    else:
        print(f"[INFO] Cabeçalho 'Server' não divulgado.")

# Teste inicial

if __name__ == "__main__":
    open("report.txt", "w").close()  # Limpa o relatório antigo

    print("========== SCANNER DE VULNERABILIDADES ==========")
    escolha = input("Deseja escanear (1) uma URL ou (2) múltiplas URLs de um arquivo? ")

    if escolha == "1":
        url = input("Digite a URL (ex: https://exemplo.com): ")
        verificar_headers(url)
        verificar_ssl(url)
        verificar_redirecionamento_https(url)

    elif escolha == "2":
        escanear_varias_urls("urls.txt")
    
    else:
        print("[ERRO] Opção inválida.")
