// Command troubadour generates memorable, security-measured passwords.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/jbro/troubadour"
	"golang.org/x/term"
)

type options struct {
	configFile    string
	wordList      string
	passwordCount int
	passwordsOnly bool
	words         troubadour.WordListConfig
	generator     troubadour.Config
}

const (
	defaultConfigPath = ".troubadour.toml"
	maxConfigSize     = 64 * 1024
	maxPasswordCount  = 1_000

	ansiReset      = "\x1b[0m"
	ansiBold       = "\x1b[1m"
	ansiBoldYellow = "\x1b[1;33m"
)

type fileConfig struct {
	WordList           string  `toml:"word-list"`
	MinWordLength      int     `toml:"min-word-length"`
	MaxWordLength      int     `toml:"max-word-length"`
	WordCount          int     `toml:"word-count"`
	PasswordCount      int     `toml:"password-count"`
	DigitCount         int     `toml:"digit-count"`
	SpecialCount       int     `toml:"special-count"`
	CalculationTimeout string  `toml:"calculation-timeout"`
	MinimumSurprisal   float64 `toml:"minimum-surprisal"`
	ExcludeRegexp      string  `toml:"exclude-regexp"`
	PasswordsOnly      bool    `toml:"passwords-only"`
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	received := make(chan syscall.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go watchSignal(ctx, cancel, signals, received, func() { signal.Stop(signals) })

	exitCode := execute(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultConfigPath)
	select {
	case receivedSignal := <-received:
		return 128 + int(receivedSignal)
	default:
	}
	return exitCode
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer, configPath string) int {
	parsed, err := parseFlags(args, stderr, configPath)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		writeDiagnostic(stderr, err)
		return 2
	}
	if err := run(ctx, parsed, stdout); err != nil {
		writeDiagnostic(stderr, err)
		return 1
	}
	return 0
}

func watchSignal(ctx context.Context, cancel context.CancelFunc, signals <-chan os.Signal, received chan<- syscall.Signal, stop func()) {
	select {
	case value := <-signals:
		stop()
		if receivedSignal, ok := value.(syscall.Signal); ok {
			received <- receivedSignal
		}
		cancel()
	case <-ctx.Done():
	}
}

func writeDiagnostic(output io.Writer, err error) {
	if _, writeErr := fmt.Fprintln(output, err); writeErr != nil {
		return
	}
}

func writeUsage(output io.Writer, defaults options, configPath string) error {
	_, err := fmt.Fprintf(output, `Usage: troubadour [options]

Generate memorable word-based passwords using cryptographically secure randomness.
The word list must contain one safe, whitespace-free, NFC-normalized UTF-8 candidate per line.
Candidates are deduplicated after filtering and resource limits are enforced.
Lengths count Unicode code points, not user-perceived grapheme clusters.
Requested digits and punctuation are inserted inside words, never at word boundaries.
Raw entropy shows the character search space; generation estimates assume known parameters.
Password generation fails if the exact collision-adjusted estimate cannot be calculated.
Set --minimum-surprisal=0 only to explicitly permit weak output.

Options:
  --config PATH                    configuration file (default %q)
  --word-list PATH                 required word-list file
  --min-word-length N              minimum candidate length in Unicode code points (default %d)
  --max-word-length N              maximum candidate length in Unicode code points (default %d)
  --word-count N                   words per password (default %d)
  --password-count N               passwords to generate (default %d)
  --digit-count N                  inserted ASCII digits per password (default %d)
  --special-count N                inserted ASCII punctuation characters per password (default %d)
  --minimum-surprisal BITS         reject generated passwords below this estimate (default %.0f)
  --calculation-timeout DURATION   collision-path calculation limit per password (default %s)
  --exclude-regexp REGEXP          Go regexp matching candidates to omit (default %q)
  --passwords-only                 print only passwords; requires explicit --config
  --help                           show this help text
`, configPath, defaults.words.MinWordLength, defaults.words.MaxWordLength, defaults.generator.WordCount, defaults.passwordCount, defaults.generator.DigitCount, defaults.generator.SpecialCount, defaults.generator.MinimumSurprisal, defaults.generator.CalculationTimeout, defaults.words.Exclude)
	return err
}

func defaultOptions() options {
	return options{
		passwordCount: 1,
		words:         troubadour.DefaultWordListConfig(),
		generator:     troubadour.DefaultConfig(),
	}
}

func expandUserPath(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	if path != "~" && (len(path) < 2 || !os.IsPathSeparator(path[1])) {
		return "", fmt.Errorf("unsupported home path %q; use ~ or a path beginning with ~/", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find user home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

func findConfigPath(args []string, fallback string) (path string, explicit, help bool, returnErr error) {
	path = fallback
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--":
			return path, explicit, help, nil
		case argument == "--help" || argument == "-h" || argument == "-help":
			help = true
		case strings.HasPrefix(argument, "--help=") || strings.HasPrefix(argument, "-help=") || strings.HasPrefix(argument, "-h="):
			value, err := strconv.ParseBool(argument[strings.IndexByte(argument, '=')+1:])
			if err == nil {
				help = value
			}
		case argument == "--config" || argument == "-config":
			if index+1 >= len(args) {
				return "", false, false, errors.New("flag needs an argument: --config")
			}
			index++
			path = args[index]
			explicit = true
		case strings.HasPrefix(argument, "--config="):
			path = strings.TrimPrefix(argument, "--config=")
			explicit = true
		case strings.HasPrefix(argument, "-config="):
			path = strings.TrimPrefix(argument, "-config=")
			explicit = true
		}
	}
	return path, explicit, help, nil
}

func readConfig(path string) (data []byte, returnErr error) {
	file, err := os.Open(path) //nolint:gosec // The path is from the user's config directory or an explicit CLI argument.
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && returnErr == nil {
			returnErr = closeErr
		}
	}()

	data, err = io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxConfigSize)
	}
	return data, nil
}

func loadConfig(path string, defaults options) (options, error) {
	data, err := readConfig(path)
	if err != nil {
		return options{}, fmt.Errorf("read config %q: %w", path, err)
	}
	config := fileConfig{
		WordList:           defaults.wordList,
		MinWordLength:      defaults.words.MinWordLength,
		MaxWordLength:      defaults.words.MaxWordLength,
		WordCount:          defaults.generator.WordCount,
		PasswordCount:      defaults.passwordCount,
		DigitCount:         defaults.generator.DigitCount,
		SpecialCount:       defaults.generator.SpecialCount,
		CalculationTimeout: defaults.generator.CalculationTimeout.String(),
		MinimumSurprisal:   defaults.generator.MinimumSurprisal,
		ExcludeRegexp:      defaults.words.Exclude,
		PasswordsOnly:      defaults.passwordsOnly,
	}
	metadata, err := toml.Decode(string(data), &config)
	if err != nil {
		return options{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for index, key := range undecoded {
			keys[index] = key.String()
		}
		return options{}, fmt.Errorf("parse config %q: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	timeout, err := time.ParseDuration(config.CalculationTimeout)
	if err != nil {
		return options{}, fmt.Errorf("parse config %q: invalid calculation-timeout: %w", path, err)
	}
	return options{
		wordList:      config.WordList,
		passwordCount: config.PasswordCount,
		passwordsOnly: config.PasswordsOnly,
		words: troubadour.WordListConfig{
			MinWordLength: config.MinWordLength,
			MaxWordLength: config.MaxWordLength,
			Exclude:       config.ExcludeRegexp,
		},
		generator: troubadour.Config{
			WordCount:          config.WordCount,
			DigitCount:         config.DigitCount,
			SpecialCount:       config.SpecialCount,
			MinimumSurprisal:   config.MinimumSurprisal,
			CalculationTimeout: timeout,
		},
	}, nil
}

func parseFlags(args []string, output io.Writer, fallbackConfigPath string) (options, error) {
	builtins := defaultOptions()
	configPath, explicitConfig, help, findErr := findConfigPath(args, fallbackConfigPath)
	if findErr != nil {
		return options{}, findErr
	}
	if help {
		if err := writeUsage(output, builtins, fallbackConfigPath); err != nil {
			return options{}, fmt.Errorf("write usage: %w", err)
		}
		return options{}, flag.ErrHelp
	}
	expandedConfigPath, expandErr := expandUserPath(configPath)
	if expandErr != nil {
		return options{}, fmt.Errorf("expand config path: %w", expandErr)
	}
	configPath = expandedConfigPath
	parsed := builtins
	if configPath != "" {
		configured, err := loadConfig(configPath, builtins)
		if err == nil {
			configured.configFile = configPath
			parsed = configured
		} else if explicitConfig || !errors.Is(err, os.ErrNotExist) {
			return options{}, err
		}
	}
	defaults := parsed
	flags := flag.NewFlagSet("troubadour", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	showHelp := false
	flags.BoolVar(&showHelp, "help", false, "show help")
	flags.BoolVar(&showHelp, "h", false, "show help")
	flags.StringVar(&configPath, "config", configPath, "configuration file")
	flags.IntVar(&parsed.words.MinWordLength, "min-word-length", parsed.words.MinWordLength, "minimum candidate length in Unicode code points")
	flags.IntVar(&parsed.words.MaxWordLength, "max-word-length", parsed.words.MaxWordLength, "maximum candidate length in Unicode code points")
	flags.IntVar(&parsed.generator.WordCount, "word-count", parsed.generator.WordCount, "number of words in each password")
	flags.IntVar(&parsed.passwordCount, "password-count", parsed.passwordCount, "number of passwords to generate")
	flags.IntVar(&parsed.generator.DigitCount, "digit-count", parsed.generator.DigitCount, "number of random ASCII digits inserted into each password")
	flags.IntVar(&parsed.generator.SpecialCount, "special-count", parsed.generator.SpecialCount, "number of random ASCII punctuation characters inserted into each password")
	flags.Float64Var(&parsed.generator.MinimumSurprisal, "minimum-surprisal", parsed.generator.MinimumSurprisal, "minimum collision-adjusted surprisal in bits; 0 explicitly permits weak output")
	flags.DurationVar(&parsed.generator.CalculationTimeout, "calculation-timeout", parsed.generator.CalculationTimeout, "maximum collision-path calculation time per password")
	flags.StringVar(&parsed.wordList, "word-list", parsed.wordList, "path to the required word-list file")
	flags.StringVar(&parsed.words.Exclude, "exclude-regexp", parsed.words.Exclude, "Go regular expression matching candidate words to exclude")
	flags.BoolVar(&parsed.passwordsOnly, "passwords-only", parsed.passwordsOnly, "print only generated passwords")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if showHelp {
		if err := writeUsage(output, defaults, fallbackConfigPath); err != nil {
			return options{}, fmt.Errorf("write usage: %w", err)
		}
		return options{}, flag.ErrHelp
	}
	if parsed.passwordsOnly && (!explicitConfig || parsed.configFile == "") {
		return options{}, errors.New("--passwords-only requires an explicitly loaded --config PATH")
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return validateOptions(parsed)
}

func validateOptions(parsed options) (options, error) {
	expandedWordList, expandErr := expandUserPath(parsed.wordList)
	if expandErr != nil {
		return options{}, fmt.Errorf("expand word-list path: %w", expandErr)
	}
	parsed.wordList = expandedWordList
	if parsed.wordList == "" {
		return options{}, errors.New("--word-list is required")
	}
	if parsed.passwordCount < 1 {
		return options{}, errors.New("password count must be greater than 0")
	}
	if parsed.passwordCount > maxPasswordCount {
		return options{}, fmt.Errorf("password count must not exceed %d", maxPasswordCount)
	}
	if err := parsed.words.Validate(); err != nil {
		return options{}, fmt.Errorf("invalid word-list configuration: %w", err)
	}
	if err := parsed.generator.Validate(); err != nil {
		return options{}, fmt.Errorf("invalid generation configuration: %w", err)
	}
	return parsed, nil
}

func run(ctx context.Context, options options, output io.Writer) (returnErr error) {
	file, err := os.Open(options.wordList)
	if err != nil {
		return fmt.Errorf("open word list: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("close word list: %w", closeErr)
		}
	}()

	words, err := troubadour.LoadWords(ctx, file, options.words)
	if err != nil {
		return fmt.Errorf("load words: %w", err)
	}
	generator, err := troubadour.NewGenerator(ctx, words, options.generator)
	if err != nil {
		return fmt.Errorf("prepare generator: %w", err)
	}
	color := supportsColor(output) && !options.passwordsOnly
	if !options.passwordsOnly {
		if err := printConfiguration(output, options, len(words), color); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return generatePasswords(ctx, generator, options, output, color)
}

func generatePasswords(ctx context.Context, generator *troubadour.Generator, options options, output io.Writer, color bool) error {
	for i := range options.passwordCount {
		result, err := generator.Generate(ctx)
		if err != nil {
			return fmt.Errorf("generate password: %w", err)
		}
		if !options.passwordsOnly && i > 0 {
			if _, err := fmt.Fprintln(output); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
		if options.passwordsOnly {
			if _, err := fmt.Fprintln(output, result.Password); err != nil {
				return fmt.Errorf("write password: %w", err)
			}
		} else if err := printResult(output, result, color); err != nil {
			return err
		}
	}
	return nil
}

func printConfiguration(output io.Writer, options options, candidateCount int, color bool) error {
	configFile := options.configFile
	if configFile == "" {
		configFile = "built-in defaults with command-line overrides"
	}
	details := []struct {
		label, value string
	}{
		{"Configuration file:", configFile},
		{"Word list:", options.wordList},
		{"Filtered candidates:", strconv.Itoa(candidateCount)},
		{"Word length:", fmt.Sprintf("%d-%d Unicode code points", options.words.MinWordLength, options.words.MaxWordLength)},
		{"Words per password:", strconv.Itoa(options.generator.WordCount)},
		{"Digits per password:", strconv.Itoa(options.generator.DigitCount)},
		{"Specials per password:", strconv.Itoa(options.generator.SpecialCount)},
		{"Minimum surprisal:", fmt.Sprintf("%.2f bits", options.generator.MinimumSurprisal)},
		{"Calculation timeout:", options.generator.CalculationTimeout.String()},
		{"Exclude regexp:", options.words.Exclude},
		{"Passwords requested:", strconv.Itoa(options.passwordCount)},
	}
	for _, detail := range details {
		if err := writeDetail(output, detail.label, detail.value, "", color); err != nil {
			return fmt.Errorf("write configuration: %w", err)
		}
	}
	return nil
}

func supportsColor(output io.Writer) bool {
	if noColor, exists := os.LookupEnv("NO_COLOR"); exists && noColor != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := output.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func styled(enabled bool, style, value string) string {
	if !enabled || style == "" {
		return value
	}
	return style + value + ansiReset
}

func writeDetail(output io.Writer, label, value, valueStyle string, color bool) error {
	paddedLabel := fmt.Sprintf("%-24s", label)
	_, err := fmt.Fprintln(output, paddedLabel+styled(color, valueStyle, value))
	return err
}

func printResult(output io.Writer, result troubadour.Result, color bool) error {
	if err := writeDetail(output, "Words:", strings.Join(result.Words, " "), ansiBoldYellow, color); err != nil {
		return fmt.Errorf("write words: %w", err)
	}
	if err := writeDetail(output, "Password:", result.Password, "", color); err != nil {
		return fmt.Errorf("write password: %w", err)
	}
	length := styled(color, ansiBold, strconv.Itoa(utf8.RuneCountInString(result.Password))) + " Unicode code points"
	if err := writeDetail(output, "Length:", length, "", color); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	rawEntropy := styled(color, ansiBold, fmt.Sprintf("%.2f", result.RawEntropy)) + " bits (character-by-character search space)"
	if err := writeDetail(output, "Raw entropy:", rawEntropy, "", color); err != nil {
		return fmt.Errorf("write raw entropy: %w", err)
	}
	label := "paths"
	if result.PathCount.IsInt64() && result.PathCount.Int64() == 1 {
		label = "path"
	}
	entropy := "collision-adjusted " + styled(color, ansiBold, fmt.Sprintf("%.2f", result.Surprisal)) + " bits (" +
		styled(color, ansiBold, result.PathCount.String()) + " valid " + label + ") | unadjusted choices " +
		styled(color, ansiBold, fmt.Sprintf("%.2f", result.Entropy)) + " bits"
	if err := writeDetail(output, "Entropy:", entropy, "", color); err != nil {
		return fmt.Errorf("write entropy: %w", err)
	}
	return nil
}
