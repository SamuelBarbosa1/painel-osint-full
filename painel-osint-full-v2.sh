#!/bin/bash
# Painel OSINT  (PT-BR)
# Autor: Samuel + GPT
# Arquivo: ~/painel-osint-full-v2.sh
# Uso: chmod +x ~/painel-osint-full-v2.sh && ./painel-osint-full-v2.sh
# Objetivo: instalar e orquestrar um conjunto amplo de ferramentas OSINT
# Observação: revise antes de rodar. Algumas instalações usam 'go install' e pipx.

set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Configurações
# -------------------------
LOGDIR="$HOME/osint-logs"
REPO_SHERLOCK="$HOME/sherlock"
VENV_DIR="$HOME/osint-venv"
KEYFILE="$HOME/.osint_keys"  # arquivo para guardar API keys (apenas texto)
GO_BIN="$HOME/go/bin"
PATH="$PATH:$GO_BIN:$HOME/.local/bin"

# -------------------------
# Cores para o terminal
# -------------------------
GREEN="\e[32m"; RED="\e[31m"; BLUE="\e[34m"; YELLOW="\e[33m"; RESET="\e[0m"

timestamp() { date +"%Y%m%d-%H%M%S"; }
ensure_logdir() { mkdir -p "$LOGDIR"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# -------------------------
# Descrições rápidas (PT-BR)
# -------------------------
# Sherlock       - pesquisa nomes de usuário em redes sociais
# TheHarvester   - coleta e-mails, subdomínios e hosts públicos
# Recon-ng       - framework modular para coleta OSINT
# Holehe         - verifica onde um e-mail está registrado
# SpiderFoot     - scanner / inteligência automatizada com UI web
# Shodan CLI     - busca por dispositivos e serviços expostos
# Amass          - enumeração de subdomínios (passivo/ativo)
# Subfinder      - enumeração de subdomínios (rápido)
# Assetfinder    - captura subdomínios via wordlists
# Gau / Waybackurls - coleta URLs históricas e de arquivamento
# Httprobe       - verifica se hosts/URLs estão vivos
# Nmap / Masscan - varredura de portas e serviços
# Gobuster / FFUF- brute-force de diretórios e fuzzing
# Nikto          - scanner web de vulnerabilidades básicas
# Aquatone       - captura screenshots de hosts/urls

# -------------------------
# Funções de instalação
# -------------------------
apt_install() {
  echo -e "${YELLOW}[*] apt install: $*${RESET}"
  sudo apt update -y
  sudo apt install -y "$@"
}

install_pipx_if_needed() {
  if ! cmd_exists pipx; then
    echo -e "${YELLOW}[i] Instalando pipx...${RESET}"
    sudo apt install -y pipx
    pipx ensurepath || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
}

install_go_if_needed() {
  if ! cmd_exists go; then
    echo -e "${YELLOW}[i] Go não encontrado. Instalando Go...${RESET}"
    apt_install golang
  fi
  mkdir -p "$HOME/go/bin"
  export PATH="$HOME/go/bin:$PATH"
}

install_common_tools() {
  echo -e "${BLUE}== Instalando dependências básicas (apt/pipx/venv) ==${RESET}"
  apt_install git python3 python3-venv python3-pip jq curl nmap masscan gobuster nikto unzip wget build-essential

  # amass costuma estar no repositório Kali
  apt_install amass || true

  # pipx e algumas ferramentas Python
  install_pipx_if_needed
  pipx ensurepath || true
  export PATH="$HOME/.local/bin:$PATH"

  # Instalar via pipx: sherlock, holehe, shodan, spiderfoot (quando disponível)
  echo -e "${BLUE}[*] Instalando pacotes Python em ambientes isolados (pipx)...${RESET}"
  pipx install --force "git+https://github.com/sherlock-project/sherlock.git" || true
  pipx install --force "git+https://github.com/megadose/holehe.git" || true
  pipx install --force shodan || true
  pipx install --force spiderfoot || true

  # Criar venv e libs auxiliares
  if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip setuptools
    pip install requests beautifulsoup4 python-whois
    deactivate
  fi

  echo -e "${GREEN}== Dependências Python instaladas (via pipx/venv) ==${RESET}"

  # Go-based tools: subfinder, assetfinder, gau, waybackurls, httprobe, ffuf, aquatone (se disponíveis)
  echo -e "${BLUE}[*] Instalando ferramentas Go (subfinder, assetfinder, gau, waybackurls, httprobe, ffuf, aquatone)...${RESET}"
  install_go_if_needed

  # Instalação via go install (usa @latest)
  GO_PKGS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/michenriksen/aquatone@latest"
  )
  for pkg in "${GO_PKGS[@]}"; do
    echo -e "${YELLOW}go install ${pkg}${RESET}"
    GO111MODULE=on go install "$pkg" || echo -e "${RED}[!] falha no go install $pkg (verifique go env)${RESET}"
  done

  echo -e "${GREEN}== Instalação GO concluída (binários em $HOME/go/bin) ==${RESET}"
  echo "OBS: Algumas ferramentas podem pedir permissoes ou ajustes de PATH. Certifique-se de que $HOME/go/bin e $HOME/.local/bin estão no PATH."
}

# -------------------------
# API Keys (integração simples)
# -------------------------
ask_and_store_api_keys() {
  echo -e "${BLUE}== Integração de API Keys (opcional) ==${RESET}"
  echo "As chaves serão salvas em: $KEYFILE (arquivo texto, permissão 600)"
  touch "$KEYFILE"
  chmod 600 "$KEYFILE"

  read -p "Deseja configurar chaves de API agora? (s/n): " yn
  if [[ "$yn" =~ ^[Ss]$ ]]; then
    read -p "Shodan API key (ENTER para pular): " shodan_key
    read -p "VirusTotal API key (ENTER para pular): " vt_key
    read -p "Hunter.io API key (ENTER para pular): " hunter_key
    read -p "Google API key (para algumas ferramentas) (ENTER para pular): " google_key

    # gravar se não vazio
    if [ -n "$shodan_key" ]; then echo "SHODAN_API_KEY=$shodan_key" >> "$KEYFILE"; fi
    if [ -n "$vt_key" ]; then echo "VIRUSTOTAL_API_KEY=$vt_key" >> "$KEYFILE"; fi
    if [ -n "$hunter_key" ]; then echo "HUNTER_API_KEY=$hunter_key" >> "$KEYFILE"; fi
    if [ -n "$google_key" ]; then echo "GOOGLE_API_KEY=$google_key" >> "$KEYFILE"; fi

    echo -e "${GREEN}Chaves salvas em $KEYFILE${RESET}"
    echo "Para carregar as chaves na sessão atual, rode: source $KEYFILE"
  else
    echo "Pulando configuração de chaves agora. Você pode editar $KEYFILE manualmente depois.";
  fi
}

# -------------------------
# Wrappers de execução com logging (PT-BR)
# -------------------------
run_and_log() {
  local name="$1"; shift
  ensure_logdir
  local outf="$LOGDIR/${name}_$(timestamp).log"
  echo -e "${BLUE}[*] Executando: $*${RESET}"
  echo -e "Comando: $*\nData: $(date)\n" > "$outf"
  ("$@") &>> "$outf" || echo -e "${RED}[!] comando retornou erro, veja $outf${RESET}"
  echo -e "${GREEN}[OK] log salvo em $outf${RESET}"
}

# -------------------------
# Funções das ferramentas (em PT-BR com descrições)
# -------------------------
sherlock_run() {
  echo -e "${YELLOW}Busca de nomes de usuário em várias plataformas (Sherlock).${RESET}"
  read -p "Nome de usuário: " user
  ensure_logdir
  local outfile="$LOGDIR/sherlock_${user}_$(timestamp).txt"
  if cmd_exists sherlock; then
    sherlock "$user" | tee "$outfile"
  elif [ -f "$REPO_SHERLOCK/sherlock/sherlock.py" ]; then
    python3 "$REPO_SHERLOCK/sherlock/sherlock.py" "$user" | tee "$outfile"
  else
    echo -e "${RED}[!] Sherlock não encontrado. Instale via pipx ou garanta que o repo esteja em $REPO_SHERLOCK${RESET}"
    return
  fi
  echo -e "${GREEN}[OK] Resultado salvo em $outfile${RESET}"
  read -p "Pressione ENTER para voltar..."
}

theharvester_run() {
  echo -e "${YELLOW}Coleta de e-mails, subdomínios e hosts (TheHarvester).${RESET}"
  read -p "Domínio (ex: example.com): " domain
  run_and_log "theharvester_${domain}" theharvester -d "$domain" -b all
  read -p "ENTER para voltar..."
}

reconng_run() {
  echo -e "${YELLOW}Iniciando Recon-ng (interface interativa). Use módulos para coletar info.${RESET}"
  recon-ng || true
}

holehe_run() {
  echo -e "${YELLOW}Verifica onde um e-mail está cadastrado (Holehe).${RESET}"
  read -p "E-mail: " email
  run_and_log "holehe_${email}" holehe "$email"
  read -p "ENTER para voltar..."
}

spiderfoot_run() {
  echo -e "${YELLOW}SpiderFoot: motor automatizado de coleta. Abre UI web na porta 5001.${RESET}"
  spiderfoot -l 127.0.0.1:5001 &
  sleep 2
  echo -e "Abra http://127.0.0.1:5001 no navegador para usar a interface gráfica."
  read -p "ENTER para voltar..."
}

shodan_run() {
  echo -e "${YELLOW}Consulta rápida via Shodan CLI. Requer chave em $KEYFILE (SHODAN_API_KEY).${RESET}"
  read -p "Consulta (IP/domínio/palavra): " q
  run_and_log "shodan_search_${q// /_}" shodan search "$q"
  read -p "ENTER para voltar..."
}

amass_run() {
  echo -e "${YELLOW}Enumeração de subdomínios com Amass (modo passivo).${RESET}"
  read -p "Domínio alvo: " domain
  run_and_log "amass_${domain}" amass enum -passive -d "$domain"
  read -p "ENTER para voltar..."
}

subdomain_chain_quick() {
  echo -e "${YELLOW}Quick Recon: encadeia amass/subfinder/assetfinder -> gau/waybackurls -> httprobe -> nmap${RESET}"
  read -p "Domínio alvo: " domain
  ensure_logdir
  local based="$LOGDIR/quick_${domain}_$(timestamp)"
  mkdir -p "$based"

  if cmd_exists amass; then
    echo -e "[*] Rodando amass (passivo) -> $based/amass.txt"
    amass enum -passive -d "$domain" -o "$based/amass.txt" || true
  fi

  if cmd_exists assetfinder; then
    echo -e "[*] Rodando assetfinder -> $based/assetfinder.txt"
    assetfinder --subs-only "$domain" | tee "$based/assetfinder.txt"
  fi

  if cmd_exists subfinder; then
    echo -e "[*] Rodando subfinder -> $based/subfinder.txt"
    subfinder -silent -d "$domain" -o "$based/subfinder.txt" || true
  fi

  # Agregar
  cat "$based/"*.txt 2>/dev/null | sed 's/\s//g' | sort -u > "$based/all-subs.txt" || true

  if cmd_exists httprobe && [ -s "$based/all-subs.txt" ]; then
    echo -e "[*] Rodando httprobe -> $based/alive.txt"
    cat "$based/all-subs.txt" | httprobe > "$based/alive.txt" || true
  fi

  if cmd_exists gau && [ -s "$based/all-subs.txt" ]; then
    echo -e "[*] Rodando gau -> $based/gau_urls.txt"
    cat "$based/all-subs.txt" | gau --threads 10 | tee "$based/gau_urls.txt" || true
  fi

  if cmd_exists waybackurls && [ -s "$based/all-subs.txt" ]; then
    echo -e "[*] Rodando waybackurls -> $based/wayback_urls.txt"
    cat "$based/all-subs.txt" | waybackurls | tee "$based/wayback_urls.txt" || true
  fi

  if [ -f "$based/alive.txt" ]; then
    cut -d':' -f1 "$based/alive.txt" | sed 's|http[s]*://||' | sort -u > "$based/hosts.txt"
    echo -e "[*] Rodando nmap nos hosts vivos -> $based/nmap.txt"
    nmap -iL "$based/hosts.txt" -oN "$based/nmap.txt" || true
  fi

  echo -e "${GREEN}[OK] Quick Recon completo. Logs em $based${RESET}"
  read -p "ENTER para voltar..."
}

masscan_run() {
  echo -e "${YELLOW}Varredura rápida de portas (masscan). Use com cuidado na rede local.${RESET}"
  read -p "Alvo (IP ou CIDR): " target
  read -p "Portas (ex: 1-65535 ou 80,443): " ports
  run_and_log "masscan_${target}" sudo masscan -p"$ports" "$target" --rate 1000
  read -p "ENTER para voltar..."
}

gobuster_run() {
  echo -e "${YELLOW}Bruteforce de diretórios com Gobuster/FFUF (enumeração de paths).${RESET}"
  read -p "URL alvo (ex: http://example.com): " url
  read -p "Wordlist (ex: /usr/share/wordlists/dirb/common.txt): " wordlist
  if cmd_exists gobuster; then
    run_and_log "gobuster_$(echo $url | sed 's/[:/]/_/g')" gobuster dir -u "$url" -w "$wordlist"
  elif cmd_exists ffuf; then
    run_and_log "ffuf_$(echo $url | sed 's/[:/]/_/g')" ffuf -u "$url/FUZZ" -w "$wordlist"
  else
    echo -e "${RED}[!] Nem gobuster nem ffuf encontrados. Instale um dos dois.${RESET}"
  fi
  read -p "ENTER para voltar..."
}

nikto_run() {
  read -p "Host alvo (ex: http://example.com): " host
  run_and_log "nikto_$(echo $host | sed 's/[:/]/_/g')" nikto -h "$host"
  read -p "ENTER para voltar..."
}

aquatone_run() {
  echo -e "${YELLOW}Aquatone: captura de screenshots de URLs/hosts (requer Chromium/Chrome).${RESET}"
  read -p "Arquivo com URLs/hosts (um por linha): " file
  if cmd_exists aquatone; then
    cat "$file" | aquatone -out "$LOGDIR/aquatone_$(timestamp)"
  else
    echo -e "${RED}[!] aquatone não encontrado. Instale via 'go install github.com/michenriksen/aquatone@latest'${RESET}"
  fi
  read -p "ENTER para voltar..."
}

# -------------------------
# Menu principal (PT-BR)
# -------------------------
menu() {
  while true; do
    clear
    echo -e "${BLUE}======================================${RESET}"
    echo -e "${BLUE}        🕵️ Painel OSINT     ${RESET}"
    echo -e "${BLUE}======================================${RESET}"
    echo -e "${GREEN}1${RESET} - Instalar dependências (apt, pipx, go, venv)"
    echo -e "${GREEN}2${RESET} - Sherlock (busca por username)"
    echo -e "${GREEN}3${RESET} - TheHarvester (recon de domínio)"
    echo -e "${GREEN}4${RESET} - Recon-ng (framework interativo)"
    echo -e "${GREEN}5${RESET} - Holehe (verificar e-mails)"
    echo -e "${GREEN}6${RESET} - SpiderFoot (UI web)"
    echo -e "${GREEN}7${RESET} - Shodan CLI (requer API key)"
    echo -e "${GREEN}8${RESET} - Amass (enumeração de subdomínios)"
    echo -e "${GREEN}9${RESET} - Quick Recon (encadeia subdomínios → URLs → nmap)"
    echo -e "${GREEN}10${RESET} - Masscan (varredura rápida de portas)"
    echo -e "${GREEN}11${RESET} - Gobuster / FFUF (fuzzing de diretórios)"
    echo -e "${GREEN}12${RESET} - Nikto (scanner web básico)"
    echo -e "${GREEN}13${RESET} - Aquatone (screenshots das URLs/hosts)"
    echo -e "${GREEN}14${RESET} - Configurar/Salvar API Keys (Shodan, VirusTotal, Hunter, Google)"
    echo -e "${GREEN}0${RESET} - Sair"
    echo ""
    read -p "Escolha: " opt
    case "$opt" in
      1) install_common_tools ;;
      2) sherlock_run ;;
      3) theharvester_run ;;
      4) reconng_run ;;
      5) holehe_run ;;
      6) spiderfoot_run ;;
      7) shodan_run ;;
      8) amass_run ;;
      9) subdomain_chain_quick ;;
      10) masscan_run ;;
      11) gobuster_run ;;
      12) nikto_run ;;
      13) aquatone_run ;;
      14) ask_and_store_api_keys ;;
      0) echo -e "${GREEN}Saindo...${RESET}"; exit 0 ;;
      *) echo -e "${RED}Opção inválida!${RESET}"; sleep 1 ;;
    esac
  done
}

# -------------------------
# Inicio
# -------------------------
ensure_logdir
menu
