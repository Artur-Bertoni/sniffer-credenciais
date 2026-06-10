# sniffer-credenciais

Sniffer didático de credenciais para a cadeira de **Segurança da Informação**.

O objetivo é reproduzir, em código, o que o Wireshark mostra em aula: capturar
tráfego de rede, identificar requisições HTTP, remontar o corpo dos `POST` de login
e extrair os campos sensíveis (usuário, senha, token) **quando o tráfego está em texto
puro (HTTP)**. Sobre **HTTPS**, o mesmo programa demonstra que só enxerga registros
TLS *Application Data* cifrados — ou seja, não consegue extrair nada legível.

> ⚠️ **Aviso ético e legal**
> Use este programa apenas em redes e máquinas para as quais você tem **permissão
> explícita**. Capturar tráfego de terceiros sem autorização é ilegal e antiético.
> Use sempre **credenciais de teste descartáveis**, nunca senhas reais — mesmo no seu
> próprio computador.

---

## O que o script faz

O [sniffer_credenciais.py](sniffer_credenciais.py) tem três modos:

| Modo       | O que faz                                                                 | Precisa de root/admin? | Precisa de scapy? |
|------------|---------------------------------------------------------------------------|:----------------------:|:-----------------:|
| `selftest` | Valida o parser de credenciais offline (sem rede).                        | Não                    | Não               |
| `http`     | Escuta uma porta HTTP em claro e **extrai credenciais** em texto puro.    | Sim                    | Sim               |
| `https`    | Escuta uma porta HTTPS e só **contabiliza tráfego cifrado** (não decifra).| Sim                    | Sim               |

Pontos técnicos relevantes:

- **Reconhece formulários e JSON** (`application/x-www-form-urlencoded` e
  `application/json`, incluindo JSON aninhado), além de um *fallback* por regex.
- **Remonta o fluxo TCP**: numa requisição real o cabeçalho HTTP e o corpo (onde ficam
  usuário/senha) chegam em pacotes separados. O sniffer acumula o payload de cada
  conexão e só extrai as credenciais quando o corpo está completo (via `Content-Length`).
- Os nomes de campo reconhecidos como usuário/senha estão em `USERNAMES` e
  `PASSWORDS` no topo do script — é só editar esses conjuntos para cobrir um campo
  customizado da sua aplicação.

---

## Pré-requisitos

- **Python 3** instalado.
- **scapy** (instalado automaticamente pelo `rodar.ps1`, ou via `pip install scapy`).
- Para captura ao vivo, uma biblioteca de captura de pacotes:
  - **Windows:** [Npcap](https://npcap.com/) — instalador à parte (vem junto com o
    Wireshark). **Marque a opção "Support loopback traffic"** durante a instalação,
    senão não dá pra capturar tráfego de `localhost`.
  - **Linux/macOS:** já vem com `libpcap`.

> No Windows o Npcap **não** está no winget/choco (a licença proíbe redistribuição) e
> o instalador gratuito **não** suporta instalação 100% silenciosa. Você baixa pelo
> terminal, mas precisa clicar no instalador (I Agree → marcar *loopback* → Install).
>
> ```powershell
> # baixa o instalador oficial mais recente e abre a janela de instalação
> $dest = "$env:USERPROFILE\Downloads\npcap.exe"
> Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.88.exe" -OutFile $dest
> Start-Process $dest
> ```

---

## Início rápido (sem rede, sem privilégios)

Valida que o parser está íntegro. Não precisa de scapy nem de Npcap:

```powershell
python sniffer_credenciais.py selftest
```

Saída esperada: `RESULTADO: 7/7 testes passaram`.

---

## Rodando localmente (Windows) — passo a passo

Para Windows há um lançador, o [rodar.ps1](rodar.ps1), que automatiza o que dá:
acha o Python certo, instala o scapy se faltar, pede elevação de Administrador sozinho
e já usa o adaptador de loopback do Npcap por padrão.

**Passo 1 — Descubra a porta certa.** Abra seu app, pressione **F12 → aba Network**,
faça um login de teste e clique na requisição de login (ex.: `POST /api/auth/login`).
Anote a **porta** que aparece na *Request URL* e se o corpo é **JSON** ou **formulário**.
Se o front usa proxy de dev (Vite/Webpack/Next), a porta a filtrar é a que aparece no
DevTools — não necessariamente a do backend.

**Passo 2 — Suba seu app local em HTTP** (front e back rodando normalmente).

**Passo 3 — Rode o sniffer** apontando para a porta anotada. O script pede Administrador
automaticamente (abre uma nova janela):

```powershell
# troque 8080 pela porta do login vista no DevTools
powershell -ExecutionPolicy Bypass -File .\rodar.ps1 -Modo http -Porta 8080
```

**Passo 4 — Faça o login** no navegador com **credenciais de teste descartáveis**.
No terminal do sniffer deve aparecer a requisição `POST` e, logo abaixo, os campos
extraídos em texto puro:

```
[HTTP] POST /api/auth/login HTTP/1.1
   [!] CREDENCIAIS EM TEXTO PURO (Content-Type: application/json):
       USUARIO | identifier = usuario_teste
       SENHA   | password = 1111
```

**Passo 5 — Encerre com `Ctrl+C`.** O programa imprime o relatório final (pacotes
observados, requisições HTTP, credenciais extraídas). Tire o print: é a evidência
do diário.

### Opções do `rodar.ps1`

```powershell
.\rodar.ps1                              # modo selftest (padrão)
.\rodar.ps1 -Modo http  -Porta 8080      # captura HTTP em loopback
.\rodar.ps1 -Modo https -Porta 443 -IP 203.0.113.10
.\rodar.ps1 -Modo http  -Porta 8080 -Iface "\Device\NPF_Loopback"
```

| Parâmetro | Padrão                  | Descrição                                                        |
|-----------|-------------------------|------------------------------------------------------------------|
| `-Modo`   | `selftest`              | `http`, `https` ou `selftest`.                                   |
| `-Porta`  | `8000`                  | Porta TCP do serviço (a do login, vista no DevTools).            |
| `-IP`     | *(vazio)*               | Restringe a captura a um IP de servidor (recomendado em produção).|
| `-Iface`  | `\Device\NPF_Loopback`  | Interface de captura. O padrão é o loopback do Npcap (localhost).|

---

## Demonstrando o HTTPS (produção)

Para fechar o comparativo, aponte o modo `https` para o **servidor real** e a porta 443.
O mesmo código que extraiu a senha no HTTP **não consegue nada aqui** — só vê bytes
cifrados:

```powershell
powershell -ExecutionPolicy Bypass -File .\rodar.ps1 -Modo https -Porta 443 -IP 203.0.113.10
```

Saída esperada (tráfego ilegível):

```
[TLS] Application Data cifrado de 203.0.113.10 | 517 bytes ilegiveis | amostra: 1703030200... ...
...
  Conclusao: trafego HTTPS so revela bytes cifrados (TLS Application Data).
  O mesmo codigo que extraiu a senha no modo HTTP nao consegue nada aqui.
```

> Capture apenas servidores que você controla / tem autorização. Em produção, prefira
> restringir com `-IP <ip-do-servidor>` para não capturar tráfego de terceiros.

---

## Linux / macOS

O script é multiplataforma; só a forma de rodar muda (sem o `rodar.ps1`). A captura
exige `sudo`:

```bash
# instalar scapy (Ubuntu recente exige a flag, ou use um venv)
pip install scapy --break-system-packages

# valida o parser (sem privilégios)
python3 sniffer_credenciais.py selftest

# captura HTTP no loopback
sudo python3 sniffer_credenciais.py http  --iface lo  --port 8080

# demonstração HTTPS de produção
sudo python3 sniffer_credenciais.py https --iface eth0 --host 203.0.113.10 --port 443
```

Nome da interface de loopback por sistema: **Linux** = `lo`, **macOS** = `lo0`,
**Windows** = `\Device\NPF_Loopback`.

---

## Solução de problemas

| Sintoma                                                | Causa provável / solução                                                                                   |
|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `Interface 'lo' not found !`                           | No Windows o loopback é `\Device\NPF_Loopback` (já é o padrão do `rodar.ps1`).                              |
| Aparece o `POST` mas nenhuma credencial                | O nome do campo não está em `USERNAMES`/`PASSWORDS`. Veja o *Request Payload* no DevTools e adicione o nome ao conjunto no início do script. |
| Nada aparece ao logar                                  | Porta errada (teste a do back **e** a do front), ou o app é HTTPS (use o modo `https`).                     |
| Tráfego só aparece cifrado no modo `http`              | O app está em HTTPS, não HTTP. Em texto puro não há o que extrair — esse é justamente o ponto da aula.       |
| `scapy nao esta instalado`                             | `pip install scapy` (o `rodar.ps1` faz isso sozinho).                                                      |
| Sem captura de `localhost` no Windows                  | O Npcap foi instalado sem a opção *"Support loopback traffic"*. Reinstale marcando essa caixa.             |
