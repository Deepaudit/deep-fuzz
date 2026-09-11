#!/usr/bin/env bash
#
# =============================================================
#  DeepFuzz - Directory & File Fuzzer em Bash puro
#  Autor: pablocybersec
#  Descrição: Ferramenta de fuzzing de diretórios/arquivos com
#             wordlist separada, alvo customizável, multithreading
#             (via xargs), filtragem por status HTTP, extensões
#             customizadas e geração automática de relatórios.
# =============================================================

set -o pipefail

# ---------- Cores ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------- Variáveis padrão ----------
TARGET=""
WORDLIST=""
EXTENSIONS=""
THREADS=10
TIMEOUT=10
USER_AGENT="DeepFuzz/1.0 (+pablocybersec)"
MATCH_CODES="200,204,301,302,307,401,403"
FILTER_CODES=""
OUTPUT_FILE=""
FOLLOW_REDIRECT=false
EXTRA_HEADERS=()
COOKIES=""
DELAY=0
QUIET=false
RECURSIVE=false
RECURSIVE_DEPTH=1
VERSION="1.0"

# ---------- Banner ----------
banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
     ____                  _____
    |  _ \  ___  ___ _ __ |  ___|   _ ________
    | | | |/ _ \/ _ \ '_ \| |_ | | | |_  /_  /
    | |_| |  __/  __/ |_) |  _|| |_| |/ / / /
    |____/ \___|\___| .__/|_|   \__,_/___/___|
                     |_|
EOF
    echo -e "${NC}${BOLD}        DeepFuzz v${VERSION} - by pablocybersec${NC}"
    echo -e "${CYAN}   Directory & File Fuzzer - Pure Bash Scripting${NC}\n"
}

# ---------- Ajuda ----------
usage() {
    banner
    cat << EOF
Uso:
  $0 -u <alvo> -w <wordlist> [opções]

Obrigatórios:
  -u, --url <url>            URL alvo (ex: http://exemplo.com/FUZZ)
                              Se "FUZZ" não for informado, é adicionado
                              automaticamente ao final da URL.
  -w, --wordlist <arquivo>   Caminho da wordlist a ser usada.

Opções:
  -x, --extensions <lista>   Extensões separadas por vírgula (ex: php,html,txt)
  -t, --threads <n>          Número de threads paralelas (padrão: ${THREADS})
  -c, --match-codes <lista>  Códigos HTTP a exibir (padrão: ${MATCH_CODES})
  -f, --filter-codes <lista> Códigos HTTP a ignorar (tem prioridade sobre -c)
  -o, --output <arquivo>     Salva relatório em arquivo (.txt)
  -H, --header <"H: V">      Header customizado (pode repetir várias vezes)
  -b, --cookie <string>      Cookies a enviar (ex: "sessao=abc123")
  -a, --agent <string>       User-Agent customizado
  -T, --timeout <segundos>   Timeout por requisição (padrão: ${TIMEOUT}s)
  -d, --delay <segundos>     Delay entre requisições de cada thread
  -r, --recursive            Ativa fuzzing recursivo em diretórios encontrados (301/2xx)
      --depth <n>            Profundidade máxima da recursão (padrão: ${RECURSIVE_DEPTH})
  -L, --follow-redirect      Segue redirecionamentos (-L do curl)
  -q, --quiet                Modo silencioso (somente resultados)
  -h, --help                 Mostra esta ajuda
  -v, --version               Mostra a versão

Exemplos:
  $0 -u http://alvo.com/FUZZ -w wordlist.txt
  $0 -u http://alvo.com -w wordlist.txt -x php,html -t 30 -o relatorio.txt
  $0 -u http://alvo.com/FUZZ -w wordlist.txt -c 200,301,403 -H "Authorization: Bearer TOKEN"
  $0 -u http://alvo.com/FUZZ -w wordlist.txt -r --depth 2

EOF
    exit 1
}

# ---------- Log ----------
log_info()  { $QUIET || echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "${RED}[x]${NC} $1" >&2; }

# ---------- Parse de argumentos ----------
parse_args() {
    if [[ $# -eq 0 ]]; then usage; fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url) TARGET="$2"; shift 2 ;;
            -w|--wordlist) WORDLIST="$2"; shift 2 ;;
            -x|--extensions) EXTENSIONS="$2"; shift 2 ;;
            -t|--threads) THREADS="$2"; shift 2 ;;
            -c|--match-codes) MATCH_CODES="$2"; shift 2 ;;
            -f|--filter-codes) FILTER_CODES="$2"; shift 2 ;;
            -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
            -H|--header) EXTRA_HEADERS+=("$2"); shift 2 ;;
            -b|--cookie) COOKIES="$2"; shift 2 ;;
            -a|--agent) USER_AGENT="$2"; shift 2 ;;
            -T|--timeout) TIMEOUT="$2"; shift 2 ;;
            -d|--delay) DELAY="$2"; shift 2 ;;
            -r|--recursive) RECURSIVE=true; shift ;;
            --depth) RECURSIVE_DEPTH="$2"; shift 2 ;;
            -L|--follow-redirect) FOLLOW_REDIRECT=true; shift ;;
            -q|--quiet) QUIET=true; shift ;;
            -v|--version) echo "DeepFuzz v${VERSION}"; exit 0 ;;
            -h|--help) usage ;;
            *) log_err "Argumento desconhecido: $1"; usage ;;
        esac
    done
}

# ---------- Validações ----------
validate_deps() {
    for cmd in curl xargs awk grep; do
        if ! command -v "$cmd" &>/dev/null; then
            log_err "Dependência ausente: $cmd. Instale antes de continuar."
            exit 1
        fi
    done
}

validate_input() {
    if [[ -z "$TARGET" ]]; then
        log_err "Alvo (-u/--url) é obrigatório."
        usage
    fi

    if [[ -z "$WORDLIST" ]]; then
        log_err "Wordlist (-w/--wordlist) é obrigatória."
        usage
    fi

    if [[ ! -f "$WORDLIST" ]]; then
        log_err "Wordlist não encontrada: $WORDLIST"
        exit 1
    fi

    if [[ ! -r "$WORDLIST" ]]; then
        log_err "Sem permissão de leitura na wordlist: $WORDLIST"
        exit 1
    fi

    if [[ -s "$WORDLIST" ]]; then :; else
        log_err "Wordlist está vazia: $WORDLIST"
        exit 1
    fi

    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        log_err "Threads inválido: $THREADS"
        exit 1
    fi

    # Garante que o alvo tenha o marcador FUZZ
    if [[ "$TARGET" != *FUZZ* ]]; then
        TARGET="${TARGET%/}/FUZZ"
        log_warn "Marcador FUZZ não encontrado na URL. Usando: $TARGET"
    fi
}

# ---------- Preparação do relatório ----------
init_report() {
    if [[ -n "$OUTPUT_FILE" ]]; then
        {
            echo "==============================================="
            echo " DeepFuzz Report - by pablocybersec"
            echo " Data: $(date '+%Y-%m-%d %H:%M:%S')"
            echo " Alvo: $TARGET"
            echo " Wordlist: $WORDLIST"
            echo " Threads: $THREADS"
            echo " Extensões: ${EXTENSIONS:-nenhuma}"
            echo "==============================================="
        } > "$OUTPUT_FILE"
    fi
}

write_report() {
    [[ -n "$OUTPUT_FILE" ]] && echo "$1" >> "$OUTPUT_FILE"
}

# ---------- Monta lista de palavras (com extensões) ----------
build_wordlist_stream() {
    local wl="$1"
    if [[ -n "$EXTENSIONS" ]]; then
        awk -v exts="$EXTENSIONS" '
            BEGIN { n = split(exts, arr, ",") }
            {
                print $0
                for (i = 1; i <= n; i++) {
                    print $0 "." arr[i]
                }
            }
        ' "$wl"
    else
        cat "$wl"
    fi
}

# ---------- Função executada por cada thread (curl) ----------
# Observação: cada chamada via xargs roda em um processo bash NOVO,
# então toda variável usada aqui precisa estar exportada (export)
# antes de ser invocada. Arrays não são exportáveis entre processos,
# por isso os headers extras e o alvo trafegam como variáveis
# de ambiente simples (strings), reconstruídas aqui dentro.
fuzz_word() {
    local word="$1"
    [[ -z "$word" || "$word" =~ ^# ]] && return

    local url="${DF_TARGET//FUZZ/$word}"
    local curl_opts=(-s -o /dev/null -w "%{http_code} %{size_download} %{url_effective}\n"
                      --max-time "${DF_TIMEOUT:-10}" -A "${DF_USER_AGENT:-DeepFuzz/1.0}")

    [[ "$DF_FOLLOW_REDIRECT" == "true" ]] && curl_opts+=(-L)
    [[ -n "$DF_COOKIES" ]] && curl_opts+=(-b "$DF_COOKIES")

    if [[ -n "$DF_EXTRA_HEADERS" ]]; then
        while IFS= read -r h; do
            [[ -n "$h" ]] && curl_opts+=(-H "$h")
        done <<< "$DF_EXTRA_HEADERS"
    fi

    if [[ -n "$DF_DELAY" && "$DF_DELAY" != "0" ]]; then
        sleep "$DF_DELAY"
    fi

    local result
    result=$(curl "${curl_opts[@]}" "$url" 2>/dev/null)
    local code size furl
    code=$(awk '{print $1}' <<< "$result")
    size=$(awk '{print $2}' <<< "$result")
    furl=$(awk '{print $3}' <<< "$result")

    [[ -z "$code" || "$code" == "000" ]] && return

    echo "${code}|${size}|${furl}"
}
export -f fuzz_word

# ---------- Empacota variáveis de estado em variáveis de ambiente ----------
# Precisa ser chamada sempre que TARGET/EXTRA_HEADERS/etc mudarem
# (inclusive antes de cada nível de recursão).
sync_env_vars() {
    export DF_TARGET="$TARGET"
    export DF_TIMEOUT="$TIMEOUT"
    export DF_USER_AGENT="$USER_AGENT"
    export DF_FOLLOW_REDIRECT="$FOLLOW_REDIRECT"
    export DF_COOKIES="$COOKIES"
    export DF_DELAY="$DELAY"
    export DF_EXTRA_HEADERS=""
    if [[ ${#EXTRA_HEADERS[@]} -gt 0 ]]; then
        DF_EXTRA_HEADERS=$(printf '%s\n' "${EXTRA_HEADERS[@]}")
        export DF_EXTRA_HEADERS
    fi
}

# ---------- Filtro de código de status ----------
code_allowed() {
    local code="$1"
    local list="$2"
    IFS=',' read -ra arr <<< "$list"
    for c in "${arr[@]}"; do
        [[ "$c" == "$code" ]] && return 0
    done
    return 1
}

# ---------- Cor por status code ----------
color_for_code() {
    local code="$1"
    case "$code" in
        2*) echo -e "$GREEN" ;;
        3*) echo -e "$YELLOW" ;;
        4*) echo -e "$RED" ;;
        5*) echo -e "$RED$BOLD" ;;
        *)  echo -e "$NC" ;;
    esac
}

# ---------- Processa resultados vindos do xargs ----------
process_results() {
    local found_count=0
    local found_dirs=()

    while IFS='|' read -r code size furl; do
        [[ -z "$code" ]] && continue

        if [[ -n "$FILTER_CODES" ]] && code_allowed "$code" "$FILTER_CODES"; then
            continue
        fi

        if [[ -n "$MATCH_CODES" ]] && ! code_allowed "$code" "$MATCH_CODES"; then
            continue
        fi

        local col
        col=$(color_for_code "$code")
        local line
        line=$(printf "[Status: %-3s | Tamanho: %-8s] %s" "$code" "$size" "$furl")
        echo -e "${col}${line}${NC}"
        write_report "$line"

        found_count=$((found_count + 1))

        if $RECURSIVE && [[ "$code" == 2* || "$code" == 3* ]]; then
            found_dirs+=("$furl")
        fi
    done

    echo "$found_count"
    if $RECURSIVE; then
        printf '%s\n' "${found_dirs[@]}" > /tmp/deepfuzz_recursive_$$.tmp
    fi
}

# ---------- Fuzzing recursivo ----------
run_recursive() {
    local depth="$1"
    local base_urls_file="$2"

    [[ "$depth" -gt "$RECURSIVE_DEPTH" ]] && return
    [[ ! -s "$base_urls_file" ]] && return

    while read -r base_url; do
        [[ -z "$base_url" ]] && continue
        base_url="${base_url%/}/FUZZ"
        log_info "Recursão (nível $depth) em: $base_url"

        local old_target="$TARGET"
        TARGET="$base_url"
        sync_env_vars

        build_wordlist_stream "$WORDLIST" | \
            xargs -P "$THREADS" -I {} bash -c 'fuzz_word "$@"' _ {} | \
            process_results > /tmp/deepfuzz_count_$$.tmp

        TARGET="$old_target"
        sync_env_vars

        if [[ -f /tmp/deepfuzz_recursive_$$.tmp ]]; then
            run_recursive $((depth + 1)) /tmp/deepfuzz_recursive_$$.tmp
            rm -f /tmp/deepfuzz_recursive_$$.tmp
        fi
    done < "$base_urls_file"
}

# ---------- Execução principal ----------
main() {
    parse_args "$@"
    validate_deps
    validate_input

    $QUIET || banner

    log_info "Alvo:      $TARGET"
    log_info "Wordlist:  $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') linhas)"
    log_info "Threads:   $THREADS"
    [[ -n "$EXTENSIONS" ]] && log_info "Extensões: $EXTENSIONS"
    log_info "Filtro (match): ${MATCH_CODES:-todos}"
    [[ -n "$FILTER_CODES" ]] && log_info "Filtro (ignorar): $FILTER_CODES"
    echo ""

    init_report

    local start_time end_time total_found
    start_time=$(date +%s)

    sync_env_vars
    total_found=$(build_wordlist_stream "$WORDLIST" | \
        xargs -P "$THREADS" -I {} bash -c 'fuzz_word "$@"' _ {} | \
        process_results | tail -n 1)

    if $RECURSIVE && [[ -f /tmp/deepfuzz_recursive_$$.tmp ]]; then
        run_recursive 2 /tmp/deepfuzz_recursive_$$.tmp
        rm -f /tmp/deepfuzz_recursive_$$.tmp
    fi

    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    echo ""
    log_ok "Fuzzing concluído em ${elapsed}s. Resultados encontrados: ${total_found:-0}"
    write_report ""
    write_report "Fuzzing concluído em ${elapsed}s. Total de resultados: ${total_found:-0}"

    if [[ -n "$OUTPUT_FILE" ]]; then
        log_ok "Relatório salvo em: $OUTPUT_FILE"
    fi
}

main "$@"
