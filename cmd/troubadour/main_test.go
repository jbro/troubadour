package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jbro/troubadour"
)

func TestHelpDocumentsCanonicalFlagsAndSemantics(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	_, err := parseTestFlags(t, []string{"--help"}, &output)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp", err)
	}
	help := output.String()
	for _, text := range []string{"--config PATH", ".troubadour.toml", "--word-list PATH", "--word-count", "--min-word-length", "--minimum-surprisal", "--calculation-timeout", "--passwords-only", "attacker knows", "Unicode code points", "NFC-normalized UTF-8"} {
		if !strings.Contains(help, text) {
			t.Errorf("help does not contain %q:\n%s", text, help)
		}
	}
	for _, obsolete := range []string{"-d ", "-s ", "-min-length ", "Unicode characters"} {
		if strings.Contains(help, obsolete) {
			t.Errorf("help contains obsolete text %q", obsolete)
		}
	}
}

func TestEquivalentHelpFormsUseIdenticalDefaults(t *testing.T) {
	t.Parallel()

	fallback := filepath.Join(t.TempDir(), "config.toml")
	var plain bytes.Buffer
	if _, err := parseFlags([]string{"--help"}, &plain, fallback); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("plain help error = %v", err)
	}
	var assigned bytes.Buffer
	if _, err := parseFlags([]string{"--help=true"}, &assigned, fallback); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("assigned help error = %v", err)
	}
	if plain.String() != assigned.String() {
		t.Fatalf("help output differs:\nplain:\n%s\nassigned:\n%s", plain.String(), assigned.String())
	}
}

func TestDefaultConfigPathUsesUserConfigDirectory(t *testing.T) {
	t.Parallel()

	path, err := defaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(directory, "troubadour", "config.toml")
	if path != want || !filepath.IsAbs(path) {
		t.Fatalf("config path = %q, want absolute path %q", path, want)
	}
}

func TestWatchSignalCancelsAndRestoresDefaultHandling(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signals := make(chan os.Signal, 1)
	received := make(chan syscall.Signal, 1)
	stopped := make(chan struct{})
	go watchSignal(ctx, cancel, signals, received, func() { close(stopped) })
	signals <- syscall.SIGINT

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal did not cancel context")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("signal notification was not stopped")
	}
	select {
	case got := <-received:
		if got != syscall.SIGINT {
			t.Fatalf("signal = %v, want SIGINT", got)
		}
	default:
		t.Fatal("signal was not recorded")
	}
}

func TestParseFlagsUsesTypedCanonicalNames(t *testing.T) {
	t.Parallel()

	parsed, err := parseTestFlags(t, []string{
		"--word-list", "words.txt",
		"--word-count", "4",
		"--password-count", "2",
		"--digit-count", "2",
		"--minimum-surprisal", "72",
		"--calculation-timeout", "750ms",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.wordList != "words.txt" || parsed.generator.WordCount != 4 || parsed.passwordCount != 2 || parsed.generator.DigitCount != 2 || parsed.generator.MinimumSurprisal != 72 || parsed.generator.CalculationTimeout != 750*time.Millisecond {
		t.Fatalf("parsed options = %+v", parsed)
	}
}

func TestParseFlagsOwnsDiagnostics(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	_, err := parseTestFlags(t, []string{"--does-not-exist"}, &output)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if output.Len() != 0 {
		t.Fatalf("parseFlags wrote duplicate diagnostic %q", output.String())
	}
}

func TestParseFlagsRequiresWordList(t *testing.T) {
	t.Parallel()

	_, err := parseTestFlags(t, nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--word-list is required") {
		t.Fatalf("error = %v, want required word-list error", err)
	}
}

func TestRunPrintsDiagnosticsByDefault(t *testing.T) {
	t.Parallel()

	wordList := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordList, []byte("cat\ndog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := options{
		wordList:      wordList,
		passwordCount: 1,
		words:         troubadour.DefaultWordListConfig(),
		generator:     troubadour.DefaultConfig(),
	}
	parsed.generator.WordCount = 1
	parsed.generator.SpecialCount = 0
	parsed.generator.MinimumSurprisal = 0
	var output bytes.Buffer
	if err := run(t.Context(), parsed, &output); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Words:", "Password:", "Unicode code points", "Generation surprisal:", "Unadjusted choices:"} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("output does not contain %q:\n%s", text, output.String())
		}
	}
}

func TestRunPrintsOnlyPasswordWhenRequested(t *testing.T) {
	t.Parallel()

	wordList := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordList, []byte("cat\ndog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := options{
		wordList:      wordList,
		passwordCount: 1,
		passwordsOnly: true,
		words:         troubadour.DefaultWordListConfig(),
		generator:     troubadour.DefaultConfig(),
	}
	parsed.generator.WordCount = 1
	parsed.generator.SpecialCount = 0
	parsed.generator.MinimumSurprisal = 0
	var output bytes.Buffer
	if err := run(t.Context(), parsed, &output); err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(output.String())
	if password == "" || strings.Contains(password, ":") || strings.Contains(password, "\n") {
		t.Fatalf("password-only output is not one plain password: %q", output.String())
	}
}

func TestRunPrintsRequestedPasswordCount(t *testing.T) {
	t.Parallel()

	wordList := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordList, []byte("cat\ndog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := options{
		wordList:      wordList,
		passwordCount: 2,
		passwordsOnly: true,
		words:         troubadour.DefaultWordListConfig(),
		generator:     troubadour.DefaultConfig(),
	}
	parsed.generator.WordCount = 1
	parsed.generator.SpecialCount = 0
	parsed.generator.MinimumSurprisal = 0
	var output bytes.Buffer
	if err := run(t.Context(), parsed, &output); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(output.String()), "\n"); len(lines) != 2 {
		t.Fatalf("password lines = %d, want 2: %q", len(lines), output.String())
	}
}

func TestRunPropagatesOutputFailure(t *testing.T) {
	t.Parallel()

	wordList := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordList, []byte("cat\ndog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := options{
		wordList:      wordList,
		passwordCount: 1,
		passwordsOnly: true,
		words:         troubadour.DefaultWordListConfig(),
		generator:     troubadour.DefaultConfig(),
	}
	parsed.generator.WordCount = 1
	parsed.generator.SpecialCount = 0
	parsed.generator.MinimumSurprisal = 0
	if err := run(t.Context(), parsed, errorWriter{}); err == nil || !strings.Contains(err.Error(), "write password") {
		t.Fatalf("error = %v, want output failure", err)
	}
}

func TestPrintResultDetailedOutput(t *testing.T) {
	t.Parallel()

	pathCount := new(big.Int).Lsh(big.NewInt(1), 80)
	var exactOutput bytes.Buffer
	result := troubadour.Result{ //nolint:gosec // Fixed non-secret fixture locks the detailed output format.
		Words:     []string{"correct", "horse", "battery"},
		Password:  "cor!recthorsebat2tery",
		Entropy:   71.25,
		PathCount: pathCount,
		Surprisal: 70.5,
	}
	if err := printResult(&exactOutput, result, false); err != nil {
		t.Fatal(err)
	}
	want := "Words:                  correct horse battery\n" +
		"Password:               cor!recthorsebat2tery\n" +
		"Length:                 21 Unicode code points\n" +
		"Generation surprisal:   70.50 bits (" + pathCount.String() + " valid paths)\n" +
		"Unadjusted choices:     71.25 bits\n"
	if exactOutput.String() != want {
		t.Fatalf("detailed output:\n%s\nwant:\n%s", exactOutput.String(), want)
	}

	var colorOutput bytes.Buffer
	if err := printResult(&colorOutput, result, true); err != nil {
		t.Fatal(err)
	}
	highlighted := ansiBoldYellow + "correct horse battery" + ansiReset
	if !strings.Contains(colorOutput.String(), highlighted) {
		t.Fatalf("colored output does not contain %q:\n%s", highlighted, colorOutput.String())
	}
	for _, metric := range []string{"21", "70.50", pathCount.String(), "71.25"} {
		boldMetric := ansiBold + metric + ansiReset
		if !strings.Contains(colorOutput.String(), boldMetric) {
			t.Fatalf("colored output does not contain %q:\n%s", boldMetric, colorOutput.String())
		}
	}
	if count := strings.Count(colorOutput.String(), "\x1b["); count != 10 {
		t.Fatalf("colored output contains %d ANSI sequences, want 10:\n%s", count, colorOutput.String())
	}
}

func TestParseFlagsRejectsInvalidRegexpAndExcessiveCount(t *testing.T) {
	t.Parallel()

	_, err := parseTestFlags(t, []string{"--word-list", "words.txt", "--exclude-regexp", "["}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid exclusion expression") {
		t.Fatalf("regexp error = %v", err)
	}
	_, err = parseTestFlags(t, []string{"--word-list", "words.txt", "--password-count", "1001"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "password count must not exceed") {
		t.Fatalf("password-count error = %v", err)
	}
}

func TestParseFlagsLoadsEveryConfigValueAndCLIOverrides(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "troubadour.toml")
	contents := `word-list = "configured.txt"
min-word-length = 4
max-word-length = 10
word-count = 4
password-count = 2
digit-count = 2
special-count = 3
minimum-surprisal = 72
calculation-timeout = "750ms"
exclude-regexp = "^skip$"
passwords-only = true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseFlags(nil, &bytes.Buffer{}, configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := options{
		wordList:      "configured.txt",
		passwordCount: 2,
		passwordsOnly: true,
		words: troubadour.WordListConfig{
			MinWordLength: 4,
			MaxWordLength: 10,
			Exclude:       "^skip$",
		},
		generator: troubadour.Config{
			WordCount:          4,
			DigitCount:         2,
			SpecialCount:       3,
			MinimumSurprisal:   72,
			CalculationTimeout: 750 * time.Millisecond,
		},
	}
	if parsed != want {
		t.Fatalf("configured options = %+v, want %+v", parsed, want)
	}

	parsed, err = parseFlags([]string{"--config", configPath, "--word-list", "cli.txt", "--word-count", "5", "--passwords-only=false"}, &bytes.Buffer{}, filepath.Join(t.TempDir(), "unused.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want.wordList = "cli.txt"
	want.generator.WordCount = 5
	want.passwordsOnly = false
	if parsed != want {
		t.Fatalf("overridden options = %+v, want %+v", parsed, want)
	}
}

func TestParseFlagsHandlesConfigErrorsStrictly(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.toml")
	if _, err := parseFlags([]string{"--word-list", "words.txt"}, &bytes.Buffer{}, missing); err != nil {
		t.Fatalf("missing default config: %v", err)
	}
	if _, err := parseFlags([]string{"--config", missing, "--word-list", "words.txt"}, &bytes.Buffer{}, ""); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit missing config error = %v", err)
	}

	unknown := filepath.Join(t.TempDir(), "unknown.toml")
	if err := os.WriteFile(unknown, []byte("word-list = \"words.txt\"\nunknown-option = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlags(nil, &bytes.Buffer{}, unknown); err == nil || !strings.Contains(err.Error(), "unknown keys: unknown-option") {
		t.Fatalf("unknown-key error = %v", err)
	}

	invalid := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(invalid, []byte("word-list = \"words.txt\"\ncalculation-timeout = \"later\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlags(nil, &bytes.Buffer{}, invalid); err == nil || !strings.Contains(err.Error(), "invalid calculation-timeout") {
		t.Fatalf("duration error = %v", err)
	}
}

func TestParseFlagsRejectsOversizedConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "large.toml")
	if err := os.WriteFile(configPath, bytes.Repeat([]byte{'#'}, maxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlags(nil, &bytes.Buffer{}, configPath); err == nil || !strings.Contains(err.Error(), "file exceeds") {
		t.Fatalf("oversized-config error = %v", err)
	}
}

func TestParseFlagsExpandsCurrentUserHomePaths(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTestFlags(t, []string{"--word-list", "~/.local/share/troubadour/words.txt"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".local/share/troubadour/words.txt")
	if parsed.wordList != want {
		t.Fatalf("word-list path = %q, want %q", parsed.wordList, want)
	}
	if expanded, err := expandUserPath("~"); err != nil || expanded != home {
		t.Fatalf("expanded home = %q, error = %v, want %q", expanded, err, home)
	}
	if _, err := expandUserPath("~another-user/words.txt"); err == nil || !strings.Contains(err.Error(), "unsupported home path") {
		t.Fatalf("unsupported-user error = %v", err)
	}
}

func parseTestFlags(t *testing.T, args []string, output *bytes.Buffer) (options, error) {
	t.Helper()
	return parseFlags(args, output, filepath.Join(t.TempDir(), ".troubadour.toml"))
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("output failed")
}
