package troubadour_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jbro/troubadour"
	"golang.org/x/text/unicode/norm"
)

const testCat = "cat"

func TestDefaultConfigsLoadWords(t *testing.T) {
	t.Parallel()

	words, err := troubadour.LoadWords(t.Context(), strings.NewReader("cat\ndog"), troubadour.DefaultWordListConfig())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cat", "dog"}; !slices.Equal(want, words) {
		t.Fatalf("words = %v, want %v", words, want)
	}
}

func TestDefaultConfigRequiresStrongPasswords(t *testing.T) {
	t.Parallel()

	if got := troubadour.DefaultConfig().MinimumSurprisal; got != 64 {
		t.Fatalf("minimum surprisal = %v, want 64", got)
	}
}

func TestLoadWordsFiltersLengthExclusionDuplicatesAndOversizedLines(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultWordListConfig()
	config.MinWordLength = 3
	config.MaxWordLength = 3
	config.Exclude = "^car$"
	input := strings.Repeat("x", 70_000) + "\ncat\ncar\ncat\ntoolong\nbar\n"
	words, err := troubadour.LoadWords(t.Context(), strings.NewReader(input), config)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{testCat, "bar"}; !slices.Equal(want, words) {
		t.Fatalf("words = %v, want %v", words, want)
	}
}

func TestLoadWordsRejectsInvalidAndUnsafeUnicode(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultWordListConfig()
	if _, err := troubadour.LoadWords(t.Context(), bytes.NewReader([]byte{0xff, '\n'}), config); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if _, err := troubadour.LoadWords(t.Context(), strings.NewReader("ca\t\n"), config); err == nil || !strings.Contains(err.Error(), "unsafe Unicode") {
		t.Fatalf("control-character error = %v", err)
	}
	if _, err := troubadour.LoadWords(t.Context(), strings.NewReader("ab\u202Ecd\n"), config); err == nil || !strings.Contains(err.Error(), "unsafe Unicode") {
		t.Fatalf("format-character error = %v", err)
	}
	if _, err := troubadour.LoadWords(t.Context(), strings.NewReader("cat dog\n"), config); err == nil || !strings.Contains(err.Error(), "unsafe Unicode") {
		t.Fatalf("whitespace error = %v", err)
	}
	if _, err := troubadour.LoadWords(t.Context(), strings.NewReader("cafe\u0301\n"), config); err == nil || !strings.Contains(err.Error(), "NFC-normalized") {
		t.Fatalf("normalization error = %v", err)
	}
}

func TestLoadWordsAcceptsFinalLineAndCRLF(t *testing.T) {
	t.Parallel()

	words, err := troubadour.LoadWords(t.Context(), strings.NewReader("cat\r\ndog"), troubadour.DefaultWordListConfig())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cat", "dog"}; !slices.Equal(words, want) {
		t.Fatalf("words = %v, want %v", words, want)
	}
}

func TestLoadWordsReturnsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := troubadour.LoadWords(ctx, strings.NewReader("cat\n"), troubadour.DefaultWordListConfig())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestLoadWordsReturnsReaderError(t *testing.T) {
	t.Parallel()

	_, err := troubadour.LoadWords(t.Context(), errorReader{}, troubadour.DefaultWordListConfig())
	if err == nil || !strings.Contains(err.Error(), "input failed") {
		t.Fatalf("error = %v, want reader failure", err)
	}
}

func TestGeneratorUsesRequestedCounts(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 2
	config.DigitCount = 1
	config.SpecialCount = 1
	config.MinimumSurprisal = 0
	generator := newGenerator(t, []string{testCat, "dog"}, config)
	result, err := generator.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := utf8.RuneCountInString(result.Password); got != 8 {
		t.Fatalf("password length = %d, want 8", got)
	}
	if got := countDigits(result.Password); got != config.DigitCount {
		t.Fatalf("digit count = %d, want %d", got, config.DigitCount)
	}
	if got := countSpecials(result.Password); got != config.SpecialCount {
		t.Fatalf("special count = %d, want %d", got, config.SpecialCount)
	}
	if len(result.Words) != config.WordCount || !slices.Contains([]string{testCat, "dog"}, result.Words[0]) || !slices.Contains([]string{testCat, "dog"}, result.Words[1]) {
		t.Fatalf("selected words = %v", result.Words)
	}
	if result.PathCount == nil || result.PathCount.Sign() == 0 {
		t.Fatalf("expected collision calculation, got paths=%v surprisal=%v", result.PathCount, result.Surprisal)
	}
}

func TestGeneratorReportsExactEntropyForTinySpace(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.DigitCount = 1
	config.SpecialCount = 0
	config.MinimumSurprisal = 0
	generator := newGenerator(t, []string{"abc"}, config)
	result, err := generator.Generate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := math.Log2(20) // Two insertion positions and ten possible digits.
	if math.Abs(result.Entropy-want) > 1e-12 {
		t.Fatalf("entropy = %v, want %v", result.Entropy, want)
	}
	if result.PathCount.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("path count = %s, want 1", result.PathCount)
	}
	if math.Abs(result.Surprisal-want) > 1e-12 {
		t.Fatalf("surprisal = %v, want %v", result.Surprisal, want)
	}
	if rawWant := 4 * math.Log2(13); math.Abs(result.RawEntropy-rawWant) > 1e-12 {
		t.Fatalf("raw entropy = %v, want %v", result.RawEntropy, rawWant)
	}
}

func TestGeneratorRejectsWeakResultByDefault(t *testing.T) {
	t.Parallel()

	generator := newGenerator(t, []string{"cat"}, troubadour.DefaultConfig())
	_, err := generator.Generate(t.Context())
	if err == nil || !strings.Contains(err.Error(), "below the configured minimum") {
		t.Fatalf("error = %v, want minimum-surprisal rejection", err)
	}
}

func TestGeneratorFailsWhenPathCountTimesOut(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.SpecialCount = 0
	config.CalculationTimeout = time.Nanosecond
	generator := newGenerator(t, []string{"abc"}, config)
	_, err := generator.Generate(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestNewGeneratorRejectsSelectionDependentInsertionCapacity(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.DigitCount = 2
	config.SpecialCount = 0
	_, err := troubadour.NewGenerator(t.Context(), []string{"aa", "bbb"}, config)
	if err == nil || !strings.Contains(err.Error(), "every possible selection") {
		t.Fatalf("error = %v, want deterministic capacity error", err)
	}
}

func TestNewGeneratorRejectsDuplicateShortAndUnsafeWords(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.SpecialCount = 0
	if _, err := troubadour.NewGenerator(t.Context(), []string{testCat, testCat}, config); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := troubadour.NewGenerator(t.Context(), []string{"a"}, config); err == nil || !strings.Contains(err.Error(), "at least two") {
		t.Fatalf("length error = %v", err)
	}
	if _, err := troubadour.NewGenerator(t.Context(), []string{"ca\t"}, config); err == nil || !strings.Contains(err.Error(), "unsafe Unicode") {
		t.Fatalf("unsafe-word error = %v", err)
	}
	if _, err := troubadour.NewGenerator(t.Context(), []string{string([]byte{0xff, 0xfe})}, config); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	if _, err := troubadour.NewGenerator(t.Context(), []string{strings.Repeat("a", 65)}, config); err == nil || !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("oversized-word error = %v", err)
	}
}

func TestNewGeneratorReturnsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := troubadour.NewGenerator(ctx, []string{testCat}, troubadour.DefaultConfig())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestGenerateReturnsParentCancellation(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.SpecialCount = 0
	generator := newGenerator(t, []string{testCat}, config)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := generator.Generate(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestConfigRejectsInsertionOverflow(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.DigitCount = math.MaxInt
	config.SpecialCount = 1
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("error = %v, want overflow error", err)
	}
}

func TestConfigRejectsInvalidMinimumSurprisal(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.MinimumSurprisal = math.NaN()
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "finite non-negative") {
		t.Fatalf("error = %v, want finite minimum-surprisal error", err)
	}
}

func TestConfigsRejectUnboundedWorkAndInvalidRegexp(t *testing.T) {
	t.Parallel()

	generation := troubadour.DefaultConfig()
	generation.WordCount = math.MaxInt
	if err := generation.Validate(); err == nil || !strings.Contains(err.Error(), "word count must not exceed") {
		t.Fatalf("word-count error = %v", err)
	}

	words := troubadour.DefaultWordListConfig()
	words.MaxWordLength = 65
	if err := words.Validate(); err == nil || !strings.Contains(err.Error(), "maximum word length must not exceed") {
		t.Fatalf("word-length error = %v", err)
	}
	words = troubadour.DefaultWordListConfig()
	words.Exclude = "["
	if err := words.Validate(); err == nil || !strings.Contains(err.Error(), "invalid exclusion expression") {
		t.Fatalf("regexp error = %v", err)
	}
}

func TestCountGenerationPathsCountsAmbiguousBoundaries(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 2
	config.SpecialCount = 0
	generator := newGenerator(t, []string{"ab", "abc", "cde", "de"}, config)
	paths, err := generator.CountGenerationPaths(t.Context(), "abcde")
	if err != nil {
		t.Fatal(err)
	}
	if paths.Int64() != 2 {
		t.Fatalf("paths = %s, want 2", paths)
	}
}

func TestCountGenerationPathsCountsAmbiguousInsertions(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.DigitCount = 1
	config.SpecialCount = 0
	generator := newGenerator(t, []string{"ab2c", "a1bc"}, config)
	paths, err := generator.CountGenerationPaths(t.Context(), "a1b2c")
	if err != nil {
		t.Fatal(err)
	}
	if paths.Int64() != 2 {
		t.Fatalf("paths = %s, want 2", paths)
	}
}

func TestCountGenerationPathsExceedsUint64(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 64
	config.SpecialCount = 0
	words := make([]string, 0, 7)
	for length := 2; length <= 8; length++ {
		words = append(words, strings.Repeat("a", length))
	}
	generator := newGenerator(t, words, config)
	paths, err := generator.CountGenerationPaths(t.Context(), strings.Repeat("a", 320))
	if err != nil {
		t.Fatal(err)
	}
	if paths.BitLen() <= 64 {
		t.Fatalf("path count = %s (bit length %d), want more than 64 bits", paths, paths.BitLen())
	}
}

func TestCountGenerationPathsHonorsCancellationDuringWalk(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.SpecialCount = 0
	generator := newGenerator(t, []string{"abcdefgh"}, config)
	ctx := newCancelAfterChecks(3)
	_, err := generator.CountGenerationPaths(ctx, "abcdefgh")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestCountGenerationPathsHonorsCancellationAfterStatesDie(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.WordCount = 1
	config.SpecialCount = 0
	generator := newGenerator(t, []string{"abcdefgh"}, config)
	ctx := newCancelAfterChecks(6)
	_, err := generator.CountGenerationPaths(ctx, strings.Repeat("z", 1_000))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestCountGenerationPathsRejectsOversizedInputAndZeroGenerator(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.SpecialCount = 0
	generator := newGenerator(t, []string{"cat"}, config)
	if _, err := generator.CountGenerationPaths(t.Context(), strings.Repeat("a", 5_000)); err == nil || !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("oversized-password error = %v", err)
	}

	zero := new(troubadour.Generator)
	if _, err := zero.CountGenerationPaths(t.Context(), "cat"); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("zero-generator count error = %v", err)
	}
	if _, err := zero.Generate(t.Context()); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("zero-generator generation error = %v", err)
	}
}

func TestCountGenerationPathsMatchesExhaustiveOracle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		words  []string
		config troubadour.Config
	}{
		{
			name:  "mixed insertions and existing category characters",
			words: []string{"ab2c", "a1bc"},
			config: func() troubadour.Config {
				config := troubadour.DefaultConfig()
				config.WordCount = 1
				config.DigitCount = 1
				config.SpecialCount = 1
				return config
			}(),
		},
		{
			name:  "repeated digits varying lengths and unicode",
			words: []string{"åbc", "abcd"},
			config: func() troubadour.Config {
				config := troubadour.DefaultConfig()
				config.WordCount = 1
				config.DigitCount = 2
				config.SpecialCount = 0
				return config
			}(),
		},
		{
			name:  "multiple words and ambiguous boundaries",
			words: []string{"ab", "aba", "ba"},
			config: func() troubadour.Config {
				config := troubadour.DefaultConfig()
				config.WordCount = 2
				config.SpecialCount = 0
				return config
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			generator := newGenerator(t, test.words, test.config)
			for password, want := range enumerateGenerationPaths(test.words, test.config) {
				got, err := generator.CountGenerationPaths(t.Context(), password)
				if err != nil {
					t.Fatalf("password %q: %v", password, err)
				}
				if got.Cmp(want) != 0 {
					t.Fatalf("password %q: paths = %s, want %s", password, got, want)
				}
			}
		})
	}
}

func TestLog2Combination(t *testing.T) {
	t.Parallel()

	if got := troubadour.Log2Combination(4, 2); math.Abs(got-math.Log2(6)) > 1e-12 {
		t.Fatalf("combination = %v, want %v", got, math.Log2(6))
	}
	if got := troubadour.Log2Combination(4, -1); !math.IsInf(got, -1) {
		t.Fatalf("invalid combination = %v, want negative infinity", got)
	}
}

func FuzzLoadWords(f *testing.F) {
	f.Add([]byte("cat\ndog\n"))
	f.Add([]byte{0xff, '\n'})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4_096 {
			t.Skip()
		}
		config := troubadour.DefaultWordListConfig()
		words, err := troubadour.LoadWords(t.Context(), bytes.NewReader(input), config)
		if err != nil {
			return
		}
		seen := make(map[string]struct{}, len(words))
		for _, word := range words {
			if !utf8.ValidString(word) || !norm.NFC.IsNormalString(word) {
				t.Fatalf("invalid normalized output %q", word)
			}
			length := utf8.RuneCountInString(word)
			if length < config.MinWordLength || length > config.MaxWordLength {
				t.Fatalf("output length %d is outside configured range", length)
			}
			for _, char := range word {
				if unicode.IsSpace(char) || unicode.IsControl(char) || unicode.Is(unicode.Cf, char) || unicode.Is(unicode.Zl, char) || unicode.Is(unicode.Zp, char) {
					t.Fatalf("unsafe output code point %U", char)
				}
			}
			if _, exists := seen[word]; exists {
				t.Fatalf("duplicate output word %q", word)
			}
			seen[word] = struct{}{}
		}
	})
}

func FuzzCountGenerationPaths(f *testing.F) {
	config := troubadour.DefaultConfig()
	config.WordCount = 2
	config.DigitCount = 1
	config.SpecialCount = 1
	generator, err := troubadour.NewGenerator(context.Background(), []string{"ab2c", "a1bc", "café"}, config)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("a1b!2ca1bc")
	f.Add(string([]byte{0xff}))
	f.Fuzz(func(t *testing.T, password string) {
		if len(password) > 256 {
			t.Skip()
		}
		paths, err := generator.CountGenerationPaths(t.Context(), password)
		if !utf8.ValidString(password) {
			if err == nil {
				t.Fatal("invalid UTF-8 password was accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if paths.Sign() < 0 {
			t.Fatalf("negative path count %s", paths)
		}
	})
}

func BenchmarkGenerate(b *testing.B) {
	config := troubadour.DefaultConfig()
	config.MinimumSurprisal = 0
	generator, err := troubadour.NewGenerator(b.Context(), []string{"correct", "horse", "battery", "staple"}, config)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := generator.Generate(b.Context()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCountGenerationPaths(b *testing.B) {
	config := troubadour.DefaultConfig()
	generator, err := troubadour.NewGenerator(b.Context(), []string{"correct", "horse", "battery", "staple"}, config)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := generator.CountGenerationPaths(b.Context(), "cor!recthorsestaple"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewGeneratorLargeDictionary(b *testing.B) {
	words := make([]string, 10_000)
	for index := range words {
		words[index] = fmt.Sprintf("word%05d", index)
	}
	config := troubadour.DefaultConfig()
	b.ResetTimer()
	for range b.N {
		if _, err := troubadour.NewGenerator(b.Context(), words, config); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGeneratorSupportsConcurrentUse(t *testing.T) {
	t.Parallel()

	config := troubadour.DefaultConfig()
	config.MinimumSurprisal = 0
	generator := newGenerator(t, []string{"correct", "horse", "battery", "staple"}, config)
	ctx := t.Context()
	failures := make(chan error, 16)
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			_, err := generator.Generate(ctx)
			failures <- err
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func enumerateGenerationPaths(words []string, config troubadour.Config) map[string]*big.Int { //nolint:gocognit // The recursive exhaustive oracle intentionally enumerates each combinatorial generation phase.
	outputs := make(map[string]*big.Int)
	selected := make([]string, config.WordCount)
	var selectWords func(int)
	selectWords = func(index int) {
		if index < len(selected) {
			for _, word := range words {
				selected[index] = word
				selectWords(index + 1)
			}
			return
		}

		base := make([]rune, 0)
		positions := make([]int, 0)
		for _, word := range selected {
			chars := []rune(word)
			offset := len(base)
			base = append(base, chars...)
			for position := 1; position < len(chars); position++ {
				positions = append(positions, offset+position)
			}
		}
		insertions := make(map[int]rune)
		enumerateCategory(positions, config.DigitCount, []rune(troubadour.Digits), insertions, func() {
			remaining := make([]int, 0, len(positions)-len(insertions))
			for _, position := range positions {
				if _, used := insertions[position]; !used {
					remaining = append(remaining, position)
				}
			}
			enumerateCategory(remaining, config.SpecialCount, []rune(troubadour.SpecialCharacters), insertions, func() {
				password := make([]rune, 0, len(base)+len(insertions))
				for position, char := range base {
					if inserted, ok := insertions[position]; ok {
						password = append(password, inserted)
					}
					password = append(password, char)
				}
				value := string(password)
				if outputs[value] == nil {
					outputs[value] = new(big.Int)
				}
				outputs[value].Add(outputs[value], big.NewInt(1))
			})
		})
	}
	selectWords(0)
	return outputs
}

func enumerateCategory(positions []int, count int, alphabet []rune, insertions map[int]rune, yield func()) {
	var choose func(int, int)
	choose = func(start, remaining int) {
		if remaining == 0 {
			yield()
			return
		}
		for index := start; index <= len(positions)-remaining; index++ {
			position := positions[index]
			for _, char := range alphabet {
				insertions[position] = char
				choose(index+1, remaining-1)
			}
			delete(insertions, position)
		}
	}
	choose(0, count)
}

type cancelAfterChecks struct {
	remaining int
	done      chan struct{}
	canceled  bool
}

func newCancelAfterChecks(checks int) *cancelAfterChecks {
	return &cancelAfterChecks{remaining: checks, done: make(chan struct{})}
}

func (c *cancelAfterChecks) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterChecks) Done() <-chan struct{}       { return c.done }
func (c *cancelAfterChecks) Value(any) any               { return nil }

func (c *cancelAfterChecks) Err() error {
	if c.canceled {
		return context.Canceled
	}
	c.remaining--
	if c.remaining <= 0 {
		close(c.done)
		c.canceled = true
		return context.Canceled
	}
	return nil
}

func newGenerator(t *testing.T, words []string, config troubadour.Config) *troubadour.Generator {
	t.Helper()
	generator, err := troubadour.NewGenerator(t.Context(), words, config)
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

func countDigits(value string) int {
	count := 0
	for _, char := range value {
		if char >= '0' && char <= '9' {
			count++
		}
	}
	return count
}

func countSpecials(value string) int {
	count := 0
	for _, char := range value {
		if strings.ContainsRune(troubadour.SpecialCharacters, char) {
			count++
		}
	}
	return count
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("input failed")
}
