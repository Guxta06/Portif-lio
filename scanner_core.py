import requests, ssl, socket
from urllib.parse import urlparse
from datetime import datetime

def salvar_relatorio(texto):
    with open("report.txt", "a", encoding="utf-8") as f:
        f.write(texto + "\n")

def verificar_headers(url):
    resultado = f"\n[+] Verificando headers de segurança em: {url}\n"
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        cabecalhos_criticos = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        for h in cabecalhos_criticos:
            if h in headers:
                resultado += f"[OK] {h}: {headers[h]}\n"
            else:
                resultado += f"[ALERTA] {h} está ausente!\n"
    except Exception as e:
        resultado += f"[ERRO] Não foi possível acessar {url}: {e}\n"
    return resultado

def verificar_certificado_ssl(url):
    resultado = f"\n[+] Verificando certificado SSL de: {url}\n"
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                validade = cert['notAfter']
                resultado += f"[OK] Certificado válido para: {cert['subject'][0][0][1]}\n"
                resultado += f"[INFO] Emitido por: {cert['issuer'][0][0][1]}\n"
                resultado += f"[INFO] Expira em: {validade}\n"
    except Exception as e:
        resultado += f"[ERRO] Não foi possível verificar o certificado SSL: {e}\n"
    return resultado

def verificar_redirecionamento_https(url):
    resultado = "\n[+] Verificando redirecionamento de HTTP para HTTPS...\n"
    parsed = urlparse(url)
    http_url = f"http://{parsed.hostname}"
    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        final_url = response.url
        if final_url.startswith("https://"):
            resultado += f"[OK] Redirecionamento HTTP → HTTPS detectado: {final_url}\n"
        else:
            resultado += f"[ALERTA] Não há redirecionamento automático para HTTPS!\n"
    except Exception as e:
        resultado += f"[ERRO] Falha ao verificar redirecionamento: {e}\n"
    return resultado