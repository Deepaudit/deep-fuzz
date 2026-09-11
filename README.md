# DeepFuzz

**Directory & File Fuzzer em puro Bash Script**
Criado por **pablocybersec**

DeepFuzz é uma ferramenta de fuzzing de diretórios/arquivos web, escrita **100% em Bash**, sem dependências de Python/Go. Usa `curl` + `xargs` para paralelismo real (multithreading), permite escolher livremente a wordlist e o alvo, suporta extensões customizadas, filtros por código HTTP, fuzzing recursivo e geração automática de relatório.

> ⚠️ **Uso ético e legal.** Use o DeepFuzz apenas em sistemas que você possui ou tem autorização explícita (por escrito) para testar. Fuzzing de diretórios contra alvos sem permissão é ilegal na maioria das jurisdições e pode ser enquadrado como acesso não autorizado.

---

## Requisitos

- Bash 4+
- `curl`
- `xargs` (GNU coreutils / findutils)
- `awk`

Testado em Linux (Debian/Ubuntu/Kali). Deve funcionar em qualquer sistema com essas ferramentas (incluindo WSL).

## Instalação

```bash
git clone <este-repositorio> deepfuzz
cd deepfuzz
chmod +x deepfuzz.sh
./deepfuzz.sh -h
```

Opcional — instalar globalmente:

```bash
sudo cp deepfuzz.sh /usr/local/bin/deepfuzz
sudo chmod +x /usr/local/bin/deepfuzz
deepfuzz -h
```

## Estrutura do projeto

```
deepfuzz/
├── deepfuzz.sh              # ferramenta principal
├── README.md                # este arquivo
└── wordlists/
    └── common-small.txt     # wordlist de exemplo (substitua pela sua)
```

A wordlist e o alvo **nunca ficam fixos no código** — ambos são informados pelo usuário via `-w` e `-u`, permitindo usar qualquer wordlist própria (SecLists, listas customizadas, etc.) contra qualquer alvo autorizado.

## Uso básico

```bash
./deepfuzz.sh -u <alvo> -w <wordlist> [opções]
```

Se você não incluir o marcador `FUZZ` na URL, o DeepFuzz adiciona automaticamente no final:

```bash
./deepfuzz.sh -u http://alvo.com -w wordlists/common-small.txt
# equivalente a:
./deepfuzz.sh -u http://alvo.com/FUZZ -w wordlists/common-small.txt
```

O marcador `FUZZ` pode ficar em qualquer posição da URL:

```bash
./deepfuzz.sh -u "http://alvo.com/api/FUZZ/details" -w wordlists/common-small.txt
```

## Opções completas

| Flag | Descrição |
|---|---|
| `-u, --url <url>` | URL alvo (obrigatório). Use `FUZZ` como marcador. |
| `-w, --wordlist <arquivo>` | Caminho da wordlist (obrigatório). |
| `-x, --extensions <lista>` | Extensões separadas por vírgula (ex: `php,html,txt`). Testa a palavra pura e a palavra+extensão. |
| `-t, --threads <n>` | Threads paralelas via `xargs -P`. Padrão: 10. |
| `-c, --match-codes <lista>` | Só mostra esses códigos HTTP. Padrão: `200,204,301,302,307,401,403`. |
| `-f, --filter-codes <lista>` | Ignora esses códigos HTTP (tem prioridade sobre `-c`). |
| `-o, --output <arquivo>` | Salva relatório em texto. |
| `-H, --header "H: V"` | Header customizado (pode repetir a flag várias vezes). |
| `-b, --cookie <string>` | Cookies a enviar. |
| `-a, --agent <string>` | User-Agent customizado. |
| `-T, --timeout <seg>` | Timeout por requisição. Padrão: 10s. |
| `-d, --delay <seg>` | Delay entre requisições de cada thread (rate limiting simples). |
| `-r, --recursive` | Fuzzing recursivo: entra em diretórios encontrados (2xx/3xx). |
| `--depth <n>` | Profundidade máxima da recursão. Padrão: 1. |
| `-L, --follow-redirect` | Segue redirects (equivalente a `curl -L`). |
| `-q, --quiet` | Modo silencioso, mostra só os resultados. |
| `-h, --help` | Ajuda. |
| `-v, --version` | Versão. |

## Exemplos

**Fuzzing simples:**
```bash
./deepfuzz.sh -u http://alvo.com/FUZZ -w wordlists/common-small.txt
```

**Com extensões e mais threads, salvando relatório:**
```bash
./deepfuzz.sh -u http://alvo.com -w minha_wordlist.txt -x php,html,bak -t 40 -o relatorio.txt
```

**Filtrando apenas 200 e 403, com header de autenticação:**
```bash
./deepfuzz.sh -u http://alvo.com/FUZZ -w minha_wordlist.txt \
  -c 200,403 -H "Authorization: Bearer SEU_TOKEN"
```

**Ignorando 404 (útil quando o alvo tem WAF que sempre responde 200):**
```bash
./deepfuzz.sh -u http://alvo.com/FUZZ -w minha_wordlist.txt -f 404
```

**Fuzzing recursivo (2 níveis de profundidade):**
```bash
./deepfuzz.sh -u http://alvo.com/FUZZ -w minha_wordlist.txt -r --depth 2
```

**Com cookie de sessão e delay entre requisições:**
```bash
./deepfuzz.sh -u http://alvo.com/FUZZ -w minha_wordlist.txt \
  -b "sessionid=abc123" -d 0.2
```

## Como funciona por dentro

1. **Wordlist separada do alvo**: `-w` aponta para qualquer arquivo texto (uma palavra por linha, linhas com `#` são ignoradas). `-u` define o alvo com o marcador `FUZZ`.
2. **Geração de candidatos**: se `-x` for usado, cada palavra vira múltiplas variantes (`palavra`, `palavra.ext1`, `palavra.ext2`, ...).
3. **Multithreading real**: o fluxo de palavras é enviado para `xargs -P <threads>`, que dispara vários processos `curl` em paralelo, cada um chamando a função `fuzz_word`.
4. **Filtragem**: cada resposta HTTP é comparada contra `--match-codes` / `--filter-codes` antes de ser exibida.
5. **Relatório**: se `-o` for usado, cada linha de resultado também é gravada em disco, com cabeçalho contendo alvo, wordlist, threads e data/hora.
6. **Recursão opcional**: com `-r`, diretórios que responderam 2xx/3xx viram novos alvos (`<url_encontrada>/FUZZ`) até a profundidade definida em `--depth`.

## Notas de performance

- Para wordlists grandes (100k+ linhas), comece com `-t 20` a `-t 50` e ajuste conforme a resposta do alvo — threads demais em ambientes com WAF/rate limiting geram falsos negativos (bloqueios).
- Use `-d` para "aliviar" o alvo quando notar bloqueios (429) ou instabilidade.
- `--match-codes ""` combinado com `--filter-codes` permite trabalhar por exclusão (mostra tudo, exceto o que foi filtrado) — útil contra alvos que sempre respondem 200.

## Licença

Uso educacional e para testes de segurança autorizados. O autor (pablocybersec) e este projeto não se responsabilizam por uso indevido.
