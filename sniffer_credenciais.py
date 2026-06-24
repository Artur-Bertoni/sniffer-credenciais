import argparse
import json
import re
import sys
import time
from datetime import datetime
from urllib.parse import unquote_plus, parse_qsl


USERNAMES = {
    "user", "username", "usuario", "login", "email", "e-mail", "mail",
    "account", "conta", "cpf", "matricula", "identifier", "identificador",
}
PASSWORDS = {
    "pass", "password", "senha", "passwd", "pwd", "secret",
    "token", "access_token", "auth", "authorization", "apikey", "api_key",
}


def classificar_campo(nome):
    nome = nome.strip().lower()

    if nome in USERNAMES:
        return "usuario"
    if nome in PASSWORDS:
        return "senha"

    if any(pedaco in nome for pedaco in PASSWORDS):
        return "senha"
    if any(pedaco in nome for pedaco in USERNAMES):
        return "usuario"
    
    return None


def transforma_json_lista_pares(dados, caminho=""):
    if isinstance(dados, dict):
        pares = []
        for chave, valor in dados.items():
            novo_caminho = f"{caminho}.{chave}" if caminho else str(chave)
            pares += transforma_json_lista_pares(valor, novo_caminho)
        return pares

    if isinstance(dados, list):
        pares = []
        for indice, valor in enumerate(dados):
            pares += transforma_json_lista_pares(valor, f"{caminho}[{indice}]")
        return pares

    return [(caminho, dados)]


def pares_de_json(corpo):
    try:
        dados = json.loads(corpo)
    except (ValueError, TypeError):
        return None
    return transforma_json_lista_pares(dados)


def pares_por_regex(texto):
    padrao = r'["\']?([A-Za-z_][\w\-]*)["\']?\s*[:=]\s*["\']?([^"\'&,}\s]+)'
    return [(m.group(1), unquote_plus(m.group(2))) for m in re.finditer(padrao, texto)]


def ler_pares_do_corpo(content_type, corpo):
    tipo = (content_type or "").lower()

    if "json" in tipo:
        pares = pares_de_json(corpo)
        if pares is not None:
            return pares

    if "form-urlencoded" in tipo:
        return parse_qsl(corpo, keep_blank_values=True)

    corpo = corpo.strip()
    if corpo.startswith(("{", "[")):
        pares = pares_de_json(corpo)
        if pares:
            return pares
    if "=" in corpo and "&" in corpo:
        return parse_qsl(corpo, keep_blank_values=True)

    return pares_por_regex(corpo)


def extrair_credenciais(content_type, corpo):
    achados = []

    for campo, valor in ler_pares_do_corpo(content_type, corpo or ""):
        nome_simples = campo.split(".")[-1].split("[")[0]
        classe = classificar_campo(nome_simples)
        if classe:
            achados.append((classe, campo, str(valor)))

    return achados


def separar_requisicao_http(texto):
    if "\r\n\r\n" in texto:
        cabecalho, corpo = texto.split("\r\n\r\n", 1)
    elif "\n\n" in texto:
        cabecalho, corpo = texto.split("\n\n", 1)
    else:
        cabecalho, corpo = texto, ""

    linhas = cabecalho.replace("\r\n", "\n").split("\n")
    linha_inicial = linhas[0]
    if not re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s", linha_inicial):
        return None

    headers = {}
    for linha in linhas[1:]:
        if ":" in linha:
            nome, _, valor = linha.partition(":")
            headers[nome.strip().lower()] = valor.strip()

    return linha_inicial, headers, corpo


def eh_tls_application_data(dados):
    if len(dados) < 5:
        return False, 0
    
    tipo = dados[0]
    versao_maior = dados[1]
    tamanho = int.from_bytes(dados[3:5], "big")

    if tipo == 0x17 and versao_maior == 0x03:
        return True, tamanho
    
    return False, 0


class Estatisticas:
    def __init__(self):
        self.pacotes = 0
        self.bytes_payload = 0
        self.requisicoes_http = 0
        self.credenciais = 0
        self.registros_tls = 0
        self.bytes_cifrados = 0
        self.inicio = time.time()

    def resumo(self):
        duracao = max(time.time() - self.inicio, 1e-9)

        return {
            "pacotes_observados": self.pacotes,
            "bytes_payload_total": self.bytes_payload,
            "requisicoes_http": self.requisicoes_http,
            "credenciais_extraidas": self.credenciais,
            "registros_tls_application_data": self.registros_tls,
            "bytes_cifrados_observados": self.bytes_cifrados,
            "duracao_s": round(duracao, 2),
        }


METODOS_COM_CORPO = ("POST", "PUT", "PATCH")


def corpo_em_bytes(dados):
    for separador in (b"\r\n\r\n", b"\n\n"):
        if separador in dados:
            return dados.split(separador, 1)[1]
        
    return b""


def requisicao_esta_completa(dados, headers, metodo):
    cabecalho_completo = b"\r\n\r\n" in dados or b"\n\n" in dados
    if not cabecalho_completo:
        return False
    if metodo not in METODOS_COM_CORPO:
        return True

    tamanho_esperado = headers.get("content-length", "")
    if not tamanho_esperado.isdigit():
        return True
    
    return len(corpo_em_bytes(dados)) >= int(tamanho_esperado)


class MonitorDeTrafego:
    LIMITE_POR_CONEXAO = 65536

    def __init__(self, modo, camada_ip, camada_ipv6, camada_tcp, camada_raw):
        self.modo = modo
        self.ip = camada_ip
        self.ipv6 = camada_ipv6
        self.tcp = camada_tcp
        self.raw = camada_raw
        self.stats = Estatisticas()
        self.conexoes = {}

    def tratar(self, pkt):
        self.stats.pacotes += 1
        if not pkt.haslayer(self.raw):
            return
        dados = bytes(pkt[self.raw].load)
        self.stats.bytes_payload += len(dados)

        if self.modo == "https":
            self.analisar_tls(dados, pkt)
        else:
            self.analisar_http(dados, pkt)

    def analisar_tls(self, dados, pkt):
        eh_cifrado, tamanho = eh_tls_application_data(dados)
        if not eh_cifrado:
            return
        self.stats.registros_tls += 1
        self.stats.bytes_cifrados += tamanho
        print(f"[TLS] Application Data cifrado de {self.endereco_de_origem(pkt)} | {tamanho} bytes "
              f"ilegiveis | amostra: {dados[5:21].hex()} ...")

    def analisar_http(self, dados_novos, pkt):
        conexao = self.identificar_conexao(pkt)
        acumulado = (self.conexoes.get(conexao, b"") + dados_novos)[-self.LIMITE_POR_CONEXAO:]
        self.conexoes[conexao] = acumulado

        requisicao = separar_requisicao_http(acumulado.decode("utf-8", errors="replace"))

        if requisicao is None:
            self.conexoes.pop(conexao, None)
            return

        linha_inicial, headers, corpo = requisicao
        metodo = linha_inicial.split()[0]

        if not requisicao_esta_completa(acumulado, headers, metodo):
            return

        self.conexoes.pop(conexao, None)
        self.mostrar_requisicao(linha_inicial, headers, corpo, metodo)

    def mostrar_requisicao(self, linha_inicial, headers, corpo, metodo):
        self.stats.requisicoes_http += 1
        print(f"\n[HTTP] {linha_inicial.strip()}")

        if metodo not in METODOS_COM_CORPO or not corpo.strip():
            return

        content_type = headers.get("content-type", "")
        credenciais = extrair_credenciais(content_type, corpo)
        if not credenciais:
            print(f"   [.] Corpo sem campos sensiveis reconhecidos (Content-Type: {content_type or 'n/d'}).")
            return

        print(f"   [!] CREDENCIAIS EM TEXTO PURO (Content-Type: {content_type or 'desconhecido'}):")
        for classe, campo, valor in credenciais:
            rotulo = "USUARIO" if classe == "usuario" else "SENHA  "
            print(f"       {rotulo} | {campo} = {valor}")
            self.stats.credenciais += 1

    def identificar_conexao(self, pkt):
        if pkt.haslayer(self.ip):
            origem, destino = pkt[self.ip].src, pkt[self.ip].dst
        elif pkt.haslayer(self.ipv6):
            origem, destino = pkt[self.ipv6].src, pkt[self.ipv6].dst
        else:
            origem = destino = "?"
        porta_origem = pkt[self.tcp].sport if pkt.haslayer(self.tcp) else 0
        porta_destino = pkt[self.tcp].dport if pkt.haslayer(self.tcp) else 0
        return (origem, porta_origem, destino, porta_destino)

    def endereco_de_origem(self, pkt):
        if pkt.haslayer(self.ip):
            return pkt[self.ip].src
        if pkt.haslayer(self.ipv6):
            return pkt[self.ipv6].src
        return "?"


def imprimir_cabecalho(modo, iface, filtro):
    print("=" * 64)
    print(f"  SNIFFER DE CREDENCIAIS  |  modo={modo.upper()}")
    print("=" * 64)
    print(f"  Interface : {iface}")
    print(f"  Filtro BPF: {filtro}")
    print(f"  Inicio    : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("-" * 64)
    print("  Pressione Ctrl+C para encerrar e ver o relatorio final.")
    print("-" * 64)


def imprimir_relatorio(modo, stats):
    print("\n" + "=" * 64)
    print("  RELATORIO FINAL")
    print("=" * 64)
    for chave, valor in stats.resumo().items():
        print(f"  {chave:<32}: {valor}")
    if modo == "http" and stats.credenciais:
        print("\n  Conclusao: trafego HTTP expoe credenciais em texto puro.")
    if modo == "https" and stats.registros_tls:
        print("\n  Conclusao: trafego HTTPS so revela bytes cifrados (TLS Application Data).")
        print("  O mesmo codigo que extraiu a senha no modo HTTP nao consegue nada aqui.")
    print("=" * 64)


def rodar_captura(modo, iface, host, port, limite_pacotes):
    try:
        from scapy.all import AsyncSniffer, TCP, IP, IPv6, Raw
    except ImportError:
        print("[ERRO] scapy nao esta instalado. Rode: pip install scapy", file=sys.stderr)
        sys.exit(2)

    filtro = f"tcp port {port}"
    if host:
        filtro += f" and host {host}"

    imprimir_cabecalho(modo, iface, filtro)
    monitor = MonitorDeTrafego(modo, IP, IPv6, TCP, Raw)

    sniffer = AsyncSniffer(iface=iface, filter=filtro, prn=monitor.tratar,
                           store=0, count=limite_pacotes or 0)
    try:
        sniffer.start()
        while sniffer.running:
            sniffer.join(timeout=0.5)
    except PermissionError:
        print("[ERRO] Sem privilegios para capturar. Use sudo (Linux) ou execute como administrador.",
              file=sys.stderr)
        sys.exit(3)
    except KeyboardInterrupt:
        print("\n  Encerrando captura...")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    imprimir_relatorio(modo, monitor.stats)


def selftest():
    print("=" * 64)
    print("  AUTOTESTE OFFLINE DO EXTRATOR DE CREDENCIAIS")
    print("=" * 64)

    casos = [
        (
            "form-urlencoded (estilo aula)",
            "application/x-www-form-urlencoded",
            "user=artur&pass=senha&lembrar=1",
            {("usuario", "artur"), ("senha", "senha")},
        ),
        (
            "JSON plano (app real)",
            "application/json",
            json.dumps({"email": "artur@teste.com", "password": "senha"}),
            {("usuario", "artur@teste.com"), ("senha", "senha")},
        ),
        (
            "JSON aninhado com token",
            "application/json",
            json.dumps({"data": {"login": "artur", "credentials": {"token": "senha"}}}),
            {("usuario", "artur"), ("senha", "senha")},
        ),
        (
            "fallback sem Content-Type (JSON)",
            "",
            '{"username":"artur","senha":"senha"}',
            {("usuario", "artur"), ("senha", "senha")},
        ),
        (
            "corpo neutro (sem credenciais)",
            "application/json",
            json.dumps({"produto": "x", "quantidade": 3}),
            set(),
        ),
    ]

    aprovados = 0
    for descricao, content_type, corpo, esperado in casos:
        achados = extrair_credenciais(content_type, corpo)
        obtido = {(classe, valor) for classe, _, valor in achados}
        passou = obtido == esperado
        aprovados += int(passou)
        print(f"  [{'PASSOU' if passou else 'FALHOU'}] {descricao}")
        if not passou:
            print(f"          esperado : {esperado}")
            print(f"          obtido   : {obtido}")

    requisicao_crua = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: 127.0.0.1:8000\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 41\r\n\r\n"
        '{"user":"artur","password":"senha"}'
    )
    partes = separar_requisicao_http(requisicao_crua)
    separador_ok = (
        partes is not None
        and partes[0].startswith("POST")
        and extrair_credenciais(partes[1].get("content-type", ""), partes[2]) != []
    )
    print(f"  [{'PASSOU' if separador_ok else 'FALHOU'}] separador de requisicao HTTP cru")
    aprovados += int(separador_ok)

    registro_tls = bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + b"\x00" * 0x20
    eh_cifrado, tamanho = eh_tls_application_data(registro_tls)
    tls_ok = eh_cifrado and tamanho == 0x20
    print(f"  [{'PASSOU' if tls_ok else 'FALHOU'}] detector de TLS Application Data")
    aprovados += int(tls_ok)

    total = len(casos) + 2
    print("-" * 64)
    print(f"  RESULTADO: {aprovados}/{total} testes passaram")
    print("=" * 64)
    return 0 if aprovados == total else 1


def main():
    parser = argparse.ArgumentParser(
        description="Sniffer didatico de credenciais HTTP vs HTTPS (Seguranca da Informacao).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  sudo python3 sniffer_credenciais.py http  --iface lo  --port 8000\n"
            "  sudo python3 sniffer_credenciais.py https --iface eth0 --host 203.0.113.10 --port 443\n"
            "  python3 sniffer_credenciais.py selftest\n\n"
            "Interface de loopback por sistema:\n"
            "  Linux  : lo\n"
            "  macOS  : lo0\n"
            "  Windows: \\Device\\NPF_Loopback (precisa do Npcap com suporte a loopback)\n"
        ),
    )
    parser.add_argument("modo", choices=["http", "https", "selftest"],
                        help="http: extrai credenciais em claro | https: conta trafego cifrado | selftest: valida o extrator offline")
    parser.add_argument("--iface", default="lo", help="interface de captura (padrao: lo)")
    parser.add_argument("--host", default=None, help="restringe a captura a um IP de servidor (recomendado em producao)")
    parser.add_argument("--port", type=int, default=8000, help="porta TCP do servico (padrao: 8000)")
    parser.add_argument("--count", type=int, default=0, help="encerra apos N pacotes (0 = ilimitado)")
    args = parser.parse_args()

    if args.modo == "selftest":
        sys.exit(selftest())
    rodar_captura(args.modo, args.iface, args.host, args.port, args.count)


if __name__ == "__main__":
    main()
