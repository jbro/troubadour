# troubadour

`troubadour` is a Go CLI for generating memorable word-based passwords with
cryptographically secure randomness.

```sh
go run ./cmd/troubadour --word-list /path/to/words.txt
```

The word-list file is required and must contain one NFC-normalized UTF-8
candidate per line.
Blank, excluded, oversized, and out-of-range entries are removed, and duplicate
entries are collapsed before generation. Candidates containing control or
Unicode format code points or whitespace are rejected because they could
manipulate or create ambiguous terminal output.

## Options

```text
--config PATH                    configuration file (default user config directory)
--word-list PATH                 required word-list file
--min-word-length N              minimum candidate length in code points (default 3)
--max-word-length N              maximum candidate length in code points (default 8)
--word-count N                   words per password (default 6)
--password-count N               passwords to generate (default 1)
--digit-count N                  inserted ASCII digits (default 0)
--special-count N                inserted ASCII punctuation characters (default 1)
--minimum-surprisal BITS         reject weaker generated passwords (default 64)
--calculation-timeout DURATION   path-counting limit per password (default 5s)
--exclude-regexp REGEXP          Go regexp matching candidates to omit (default ^$)
--passwords-only                 print only passwords; requires explicit --config
```

Durations use Go syntax such as `750ms`, `5s`, or `1m`. Set
`--minimum-surprisal=0` only when deliberately accepting weak output. Lengths
count Unicode code points, not user-perceived grapheme clusters, so an insertion
may separate a base character from a combining mark. Run
`go run ./cmd/troubadour --help` for the authoritative help output.

## Configuration file

An optional `.troubadour.toml` in the current directory can set the default for
every generation and output flag. Use `--config PATH` to load another file;
command-line flags always override file values. A missing default file is
ignored, while a missing explicitly requested file is an error. Unknown keys
and invalid values are rejected.

Configuration fields omitted by older files inherit current defaults.
In particular, the minimum surprisal is 64 bits and the default word count is
six. An older file that explicitly retains a lower word count may need to be
updated to meet the strength floor; setting `minimum-surprisal = 0` is the
explicit unsafe opt-out.

```toml
word-list = "~/.local/share/troubadour/words.txt"
min-word-length = 3
max-word-length = 8
word-count = 6
password-count = 1
digit-count = 0
special-count = 1
minimum-surprisal = 64
calculation-timeout = "5s"
exclude-regexp = "^$"
passwords-only = false
```

Relative paths are interpreted from the current working directory. Both config
and word-list paths expand `~` to the current user's home directory;
`~another-user` syntax is not supported. Configuration files are limited to
64 KiB.

Insertions are placed inside words, never before the first or after the last
code point. A configuration is rejected unless every possible word selection
has enough insertion positions; generation therefore cannot randomly fail
because it selected shorter words.

## Security estimates

By default, output includes the selected source words, final password, password
length, raw entropy, generation entropy, and collision-adjusted generation
surprisal. Pass
`--passwords-only` with an explicit configuration file when piping output to
another program to print one generated password per line. Requiring
`--config PATH` ensures suppressed configuration details were deliberately
selected:

```sh
troubadour --config .troubadour.toml --passwords-only
```

```text
cor!recthor7sebatterystaple
```

Raw entropy is the password length multiplied by the base-2 logarithm of the
effective character alphabet. It represents a naive character-by-character
search space and is useful when the generation parameters and filtered word
list remain secret. It is not the entropy of the configured generation process,
because an attacker may infer or discover those parameters.

Generation entropy measures the uniformly random word, insertion-position, and
inserted-character choices. Generation surprisal further adjusts that value for
distinct generation paths that produce the same password. Path counting is
exact and uses arbitrary-precision integers. Generation fails rather than
returning a password with an unknown security estimate if path counting exceeds
`--calculation-timeout`.

Detailed output highlights the source words in bold yellow and bolds metric
numbers when standard output is a terminal. Redirected output and
`--passwords-only` remain plain text. Set the standard `NO_COLOR` environment
variable to disable styling.

Generation entropy and collision-adjusted surprisal assume an attacker knows
the generator configuration and exact filtered word list. Raw entropy presents
the alternate character-search estimate for the intended secret-parameter
threat model. The enforced minimum uses collision-adjusted surprisal rather than
relying on configuration secrecy.

The default policy rejects results below 64 bits of collision-adjusted
surprisal. Increase `--word-count` for higher-value or offline-verifier threat
models. A deliberately lower target must be requested explicitly.

Some destination systems normalize Unicode, trim values, or interpret shell
punctuation. Candidates are required to be NFC-normalized and whitespace-free,
but callers must still preserve the generated password exactly and quote it
when passing it through a shell.

Word lists are limited to 250,000 unique candidates, 4,000,000 total Unicode
code points, and 1,000,000 trie nodes. Public path-counting input is limited to
the maximum possible generated password length.

## Development

Runtime dependencies are the TOML parser, terminal detection, and Unicode
normalization packages. Development tools are pinned in the root `go.mod` with
Go's `tool` directive.

```sh
go test -race -shuffle=on ./...
go tool gofumpt -w .
go tool golangci-lint run ./...
go tool govulncheck ./...
go build ./...
```

The same verification checks run in GitHub Actions. Weekly scheduled runs also
exercise the fuzz targets, and Dependabot tracks Go and GitHub Actions updates.
`gofumpt` is also enforced by golangci-lint.
