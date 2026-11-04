// Package troubadour generates word-based passwords and measures ambiguity in
// their generation paths.
package troubadour

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// Digits is the alphabet used for generated digit insertions.
	Digits = "0123456789"
	// SpecialCharacters is the ASCII punctuation alphabet used for insertions.
	SpecialCharacters = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

	maxWordLength     = 64
	maxWordCount      = 64
	maxInsertionCount = 128
	maxCandidateCount = 250_000
	maxTotalWordRunes = 4_000_000
	maxTrieNodes      = 1_000_000
	maxPasswordRunes  = maxWordCount*maxWordLength + maxInsertionCount
	maxPasswordBytes  = maxWordCount*maxWordLength*utf8.UTFMax + maxInsertionCount
)

// WordListConfig controls candidate filtering. Lengths count Unicode code
// points, not user-perceived grapheme clusters.
type WordListConfig struct {
	// MinWordLength must be at least 2.
	MinWordLength int
	// MaxWordLength must not exceed 64.
	MaxWordLength int
	// Exclude is a Go regular expression matching candidate words to omit.
	Exclude string
}

// DefaultWordListConfig returns the default candidate-filtering configuration.
func DefaultWordListConfig() WordListConfig {
	return WordListConfig{MinWordLength: 3, MaxWordLength: 8, Exclude: "^$"}
}

// Validate checks whether the word-list configuration is internally consistent.
func (c WordListConfig) Validate() error {
	switch {
	case c.MinWordLength < 2:
		return errors.New("minimum word length must be at least 2")
	case c.MaxWordLength < 2:
		return errors.New("maximum word length must be at least 2")
	case c.MinWordLength > c.MaxWordLength:
		return errors.New("minimum word length must not exceed maximum word length")
	case c.MaxWordLength > maxWordLength:
		return fmt.Errorf("maximum word length must not exceed %d", maxWordLength)
	}
	if _, err := regexp.Compile(c.Exclude); err != nil {
		return fmt.Errorf("invalid exclusion expression: %w", err)
	}
	return nil
}

// Config controls password generation.
type Config struct {
	// WordCount must be between 1 and 64.
	WordCount int
	// DigitCount and SpecialCount must be non-negative and total at most 128.
	DigitCount   int
	SpecialCount int
	// MinimumSurprisal rejects weaker generated results. Set it to 0 only
	// when the caller deliberately accepts weak output.
	MinimumSurprisal float64
	// CalculationTimeout limits collision-path counting for each generated password.
	CalculationTimeout time.Duration
}

// DefaultConfig returns a valid generation configuration suitable for interactive use.
func DefaultConfig() Config {
	return Config{WordCount: 6, SpecialCount: 1, MinimumSurprisal: 64, CalculationTimeout: 5 * time.Second}
}

// Validate checks whether the generation configuration is internally consistent.
func (c Config) Validate() error {
	switch {
	case c.WordCount < 1:
		return errors.New("word count must be greater than 0")
	case c.WordCount > maxWordCount:
		return fmt.Errorf("word count must not exceed %d", maxWordCount)
	case c.DigitCount < 0 || c.SpecialCount < 0:
		return errors.New("insertion counts must not be negative")
	case c.DigitCount > maxInsertionCount || c.SpecialCount > maxInsertionCount-c.DigitCount:
		return fmt.Errorf("total insertion count must not exceed %d", maxInsertionCount)
	case math.IsNaN(c.MinimumSurprisal) || math.IsInf(c.MinimumSurprisal, 0) || c.MinimumSurprisal < 0:
		return errors.New("minimum surprisal must be a finite non-negative number")
	case c.CalculationTimeout <= 0:
		return errors.New("calculation timeout must be greater than 0")
	}
	return nil
}

// LoadWords reads, filters, and deduplicates one candidate per input line. It
// rejects dictionaries exceeding 250,000 candidates or 4,000,000 total code
// points.
// Cancellation is checked between reads; it cannot interrupt an io.Reader that
// is itself blocked.
func LoadWords(ctx context.Context, input io.Reader, config WordListConfig) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if input == nil {
		return nil, errors.New("input must not be nil")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	exclude, err := regexp.Compile(config.Exclude)
	if err != nil {
		return nil, fmt.Errorf("compile exclusion expression: %w", err)
	}

	seen := make(map[string]struct{})
	words := make([]string, 0)
	totalRunes := 0
	reader := bufio.NewReader(input)
	maximumBytes := config.MaxWordLength*utf8.UTFMax + 1
	lineNumber := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, oversized, readErr := readLine(ctx, reader, maximumBytes)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read word list: %w", readErr)
		}
		lineNumber++
		if oversized {
			continue
		}
		word, length, include, err := candidateWord(line, lineNumber, config, exclude)
		if err != nil {
			return nil, err
		}
		if include {
			if err := addUniqueWord(&words, seen, &totalRunes, word, length); err != nil {
				return nil, err
			}
		}
	}
	if len(words) == 0 {
		return nil, errors.New("no words match the requested criteria")
	}
	return words, nil
}

func candidateWord(line []byte, lineNumber int, config WordListConfig, exclude *regexp.Regexp) (string, int, bool, error) {
	word := string(line)
	if !utf8.ValidString(word) {
		return "", 0, false, fmt.Errorf("word list line %d is not valid UTF-8", lineNumber)
	}
	length := utf8.RuneCountInString(word)
	if length < config.MinWordLength || length > config.MaxWordLength || exclude.MatchString(word) {
		return "", 0, false, nil
	}
	if err := validateWord(word); err != nil {
		return "", 0, false, fmt.Errorf("word list line %d: %w", lineNumber, err)
	}
	return word, length, true, nil
}

func addUniqueWord(words *[]string, seen map[string]struct{}, totalRunes *int, word string, length int) error {
	if _, exists := seen[word]; exists {
		return nil
	}
	if len(*words) == maxCandidateCount {
		return fmt.Errorf("word list must not exceed %d unique candidates", maxCandidateCount)
	}
	if *totalRunes > maxTotalWordRunes-length {
		return fmt.Errorf("word list must not exceed %d total Unicode code points", maxTotalWordRunes)
	}
	seen[word] = struct{}{}
	*words = append(*words, word)
	*totalRunes += length
	return nil
}

func readLine(ctx context.Context, reader *bufio.Reader, maximumBytes int) ([]byte, bool, error) {
	line := make([]byte, 0)
	oversized := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		fragment, isPrefix, err := reader.ReadLine()
		if err != nil {
			return nil, false, err
		}
		if !oversized && len(line)+len(fragment) <= maximumBytes {
			line = append(line, fragment...)
		} else {
			line = nil
			oversized = true
		}
		if !isPrefix {
			return line, oversized, nil
		}
	}
}

func validateWord(word string) error {
	if !utf8.ValidString(word) {
		return errors.New("word is not valid UTF-8")
	}
	if !norm.NFC.IsNormalString(word) {
		return errors.New("word is not NFC-normalized Unicode")
	}
	length := 0
	for _, char := range word {
		length++
		if length > maxWordLength {
			return fmt.Errorf("word must not exceed %d Unicode code points", maxWordLength)
		}
		if unicode.IsSpace(char) || unicode.IsControl(char) || unicode.Is(unicode.Cf, char) || unicode.Is(unicode.Zl, char) || unicode.Is(unicode.Zp, char) {
			return fmt.Errorf("word contains unsafe Unicode code point %U", char)
		}
	}
	return nil
}

type preparedWord struct {
	runes []rune
}

type wordNode struct {
	children map[rune]*wordNode
	terminal bool
}

// Generator validates and preprocesses an immutable dictionary for repeated use.
type Generator struct {
	config       Config
	words        []preparedWord
	root         *wordNode
	alphabetSize int
}

type dictionaryBuilder struct {
	prepared          []preparedWord
	lookup            map[string]struct{}
	root              *wordNode
	minimumWordLength int
	totalRunes        int
	trieNodes         int
	alphabet          map[rune]struct{}
}

// NewGenerator validates and copies words, then prepares reusable lookup data.
// Every word must be unique, NFC-normalized valid UTF-8, terminal-safe, and
// between two and 64 Unicode code points long. Dictionary size and trie growth
// are bounded to prevent excessive resource use.
func NewGenerator(ctx context.Context, words []string, config Config) (*Generator, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, errors.New("word list is empty")
	}
	if len(words) > maxCandidateCount {
		return nil, fmt.Errorf("word list must not exceed %d candidates", maxCandidateCount)
	}

	builder := dictionaryBuilder{
		prepared:          make([]preparedWord, 0, len(words)),
		lookup:            make(map[string]struct{}, len(words)),
		root:              &wordNode{},
		minimumWordLength: math.MaxInt,
		trieNodes:         1,
		alphabet:          make(map[rune]struct{}),
	}
	for _, word := range words {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := builder.add(word); err != nil {
			return nil, err
		}
	}

	needed := config.DigitCount + config.SpecialCount
	positionsPerShortestWord := builder.minimumWordLength - 1
	requiredWords := needed / positionsPerShortestWord
	if needed%positionsPerShortestWord != 0 {
		requiredWords++
	}
	if config.WordCount < requiredWords {
		available := config.WordCount * positionsPerShortestWord
		return nil, fmt.Errorf("cannot insert %d characters into every possible selection; shortest selections have %d positions", needed, available)
	}
	return &Generator{
		config:       config,
		words:        builder.prepared,
		root:         builder.root,
		alphabetSize: effectiveAlphabetSize(builder.alphabet, config),
	}, nil
}

func (b *dictionaryBuilder) add(word string) error {
	if err := validateWord(word); err != nil {
		return fmt.Errorf("invalid word %q: %w", word, err)
	}
	if _, exists := b.lookup[word]; exists {
		return fmt.Errorf("word list contains duplicate %q", word)
	}
	runes := []rune(word)
	if len(runes) < 2 {
		return fmt.Errorf("word %q must contain at least two Unicode code points", word)
	}
	if b.totalRunes > maxTotalWordRunes-len(runes) {
		return fmt.Errorf("word list must not exceed %d total Unicode code points", maxTotalWordRunes)
	}
	b.totalRunes += len(runes)

	node := b.root
	for _, char := range runes {
		b.alphabet[char] = struct{}{}
		child := node.children[char]
		if child == nil {
			if b.trieNodes == maxTrieNodes {
				return fmt.Errorf("word list trie must not exceed %d nodes", maxTrieNodes)
			}
			if node.children == nil {
				node.children = make(map[rune]*wordNode)
			}
			child = &wordNode{}
			node.children[char] = child
			b.trieNodes++
		}
		node = child
	}
	node.terminal = true
	b.lookup[word] = struct{}{}
	b.prepared = append(b.prepared, preparedWord{runes: runes})
	b.minimumWordLength = min(b.minimumWordLength, len(runes))
	return nil
}

func effectiveAlphabetSize(wordAlphabet map[rune]struct{}, config Config) int {
	alphabet := maps.Clone(wordAlphabet)
	if config.DigitCount > 0 {
		for _, char := range Digits {
			alphabet[char] = struct{}{}
		}
	}
	if config.SpecialCount > 0 {
		for _, char := range SpecialCharacters {
			alphabet[char] = struct{}{}
		}
	}
	return len(alphabet)
}

// Result describes one generated password and its security estimates.
type Result struct {
	// Words contains the selected words before insertions.
	Words []string
	// Password is the final generated value.
	Password string
	// RawEntropy is log2 of the character-by-character search space for a
	// password of this length over the generator's effective alphabet. It is
	// not the entropy of the configured generation process.
	RawEntropy float64
	// Entropy is the base-2 logarithm of the unadjusted generation choices.
	Entropy float64
	// PathCount is the exact number of generation paths producing Password.
	PathCount *big.Int
	// Surprisal is the collision-adjusted generation estimate.
	Surprisal float64
}

// Generate creates one password using cryptographically secure randomness.
func (g *Generator) Generate(ctx context.Context) (Result, error) {
	return g.generate(ctx, rand.Reader)
}

func (g *Generator) generate(ctx context.Context, random io.Reader) (Result, error) {
	if g == nil {
		return Result{}, errors.New("generator must not be nil")
	}
	if g.root == nil || len(g.words) == 0 {
		return Result{}, errors.New("generator is not initialized; use NewGenerator")
	}
	if ctx == nil {
		return Result{}, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	selected, selectedWords, positions, err := g.selectWords(ctx, random)
	if err != nil {
		return Result{}, err
	}
	insertions, err := g.selectInsertions(ctx, random, positions)
	if err != nil {
		return Result{}, err
	}
	value, positionCount := assemblePassword(selected, insertions)
	entropy := float64(g.config.WordCount)*math.Log2(float64(len(g.words))) + Log2Combination(positionCount, g.config.DigitCount) + Log2Combination(positionCount-g.config.DigitCount, g.config.SpecialCount)
	entropy += float64(g.config.DigitCount)*math.Log2(float64(len(Digits))) + float64(g.config.SpecialCount)*math.Log2(float64(len(SpecialCharacters)))
	result := Result{
		Words:      selectedWords,
		Password:   value,
		RawEntropy: float64(utf8.RuneCountInString(value)) * math.Log2(float64(g.alphabetSize)),
		Entropy:    entropy,
	}

	calculationContext, cancel := context.WithTimeout(ctx, g.config.CalculationTimeout)
	defer cancel()
	paths, pathErr := g.countGenerationPaths(calculationContext, value)
	if pathErr != nil {
		return Result{}, fmt.Errorf("count generation paths: %w", pathErr)
	}
	if paths.Sign() == 0 {
		return Result{}, errors.New("unable to find the generation path for a generated password")
	}
	result.PathCount = paths
	result.Surprisal = entropy - log2BigInt(paths)
	if result.Surprisal < g.config.MinimumSurprisal {
		return Result{}, fmt.Errorf("generated password surprisal %.2f bits is below the configured minimum %.2f bits", result.Surprisal, g.config.MinimumSurprisal)
	}
	return result, nil
}

func (g *Generator) selectWords(ctx context.Context, random io.Reader) ([]preparedWord, []string, []position, error) {
	selected := make([]preparedWord, g.config.WordCount)
	selectedWords := make([]string, g.config.WordCount)
	positions := make([]position, 0, g.config.WordCount*(maxWordLength-1))
	for index := range g.config.WordCount {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		wordIndex, err := randomIndex(random, len(g.words))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("select word: %w", err)
		}
		selected[index] = g.words[wordIndex]
		selectedWords[index] = string(selected[index].runes)
		for character := 1; character < len(selected[index].runes); character++ {
			positions = append(positions, position{word: index, character: character})
		}
	}
	return selected, selectedWords, positions, nil
}

func (g *Generator) selectInsertions(ctx context.Context, random io.Reader, positions []position) ([]map[int]rune, error) {
	insertions := make([]map[int]rune, g.config.WordCount)
	for index := range insertions {
		insertions[index] = make(map[int]rune)
	}
	digits, err := randomCharacters(ctx, random, g.config.DigitCount, Digits)
	if err != nil {
		return nil, fmt.Errorf("generate digits: %w", err)
	}
	specials, err := randomCharacters(ctx, random, g.config.SpecialCount, SpecialCharacters)
	if err != nil {
		return nil, fmt.Errorf("generate special characters: %w", err)
	}
	for _, char := range digits + specials {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index, err := randomIndex(random, len(positions))
		if err != nil {
			return nil, fmt.Errorf("select insertion position: %w", err)
		}
		selectedPosition := positions[index]
		positions[index] = positions[len(positions)-1]
		positions = positions[:len(positions)-1]
		insertions[selectedPosition.word][selectedPosition.character] = char
	}
	return insertions, nil
}

func assemblePassword(selected []preparedWord, insertions []map[int]rune) (string, int) {
	password := make([]rune, 0, len(selected)*maxWordLength+maxInsertionCount)
	positionCount := 0
	for wordIndex, word := range selected {
		positionCount += len(word.runes) - 1
		for characterIndex, char := range word.runes {
			if inserted, ok := insertions[wordIndex][characterIndex]; ok {
				password = append(password, inserted)
			}
			password = append(password, char)
		}
	}
	return string(password), positionCount
}

// CountGenerationPaths counts exact generation interpretations for password.
// Inputs longer than the maximum possible generated password are rejected.
// The caller controls cancellation and deadlines through ctx; this method does
// not apply Config.CalculationTimeout.
func (g *Generator) CountGenerationPaths(ctx context.Context, password string) (*big.Int, error) {
	if g == nil {
		return nil, errors.New("generator must not be nil")
	}
	if g.root == nil || len(g.words) == 0 {
		return nil, errors.New("generator is not initialized; use NewGenerator")
	}
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	if len(password) > maxPasswordBytes {
		return nil, fmt.Errorf("password must not exceed %d Unicode code points", maxPasswordRunes)
	}
	if !utf8.ValidString(password) {
		return nil, errors.New("password is not valid UTF-8")
	}
	if utf8.RuneCountInString(password) > maxPasswordRunes {
		return nil, fmt.Errorf("password must not exceed %d Unicode code points", maxPasswordRunes)
	}
	return g.countGenerationPaths(ctx, password)
}

// Log2Combination returns log2 of "total choose selected".
func Log2Combination(total, selected int) float64 {
	if selected < 0 || selected > total || total < 0 {
		return math.Inf(-1)
	}
	if selected == 0 || total == selected {
		return 0
	}
	if selected > total-selected {
		selected = total - selected
	}
	value := 0.0
	for i := 1; i <= selected; i++ {
		value += math.Log2(float64(total-selected+i)) - math.Log2(float64(i))
	}
	return value
}

func log2BigInt(value *big.Int) float64 {
	if value.Sign() <= 0 {
		return math.Inf(-1)
	}
	bitLength := value.BitLen()
	if bitLength <= 53 {
		return math.Log2(float64(value.Uint64()))
	}
	shift := bitLength - 53
	top := new(big.Int).Rsh(new(big.Int).Set(value), uint(shift)).Uint64()
	return float64(shift) + math.Log2(float64(top))
}

type position struct{ word, character int }

func randomIndex(random io.Reader, length int) (int, error) {
	if length <= 0 {
		return 0, errors.New("random selection requires a non-empty range")
	}
	value, err := rand.Int(random, big.NewInt(int64(length)))
	if err != nil {
		return 0, fmt.Errorf("generate random index: %w", err)
	}
	return int(value.Int64()), nil
}

func randomCharacters(ctx context.Context, random io.Reader, count int, alphabet string) (string, error) {
	chars := []rune(alphabet)
	result := make([]rune, 0, count)
	for range count {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		index, err := randomIndex(random, len(chars))
		if err != nil {
			return "", err
		}
		result = append(result, chars[index])
	}
	return string(result), nil
}

func addCount[K comparable](counts map[K]*big.Int, key K, value *big.Int) {
	if counts[key] == nil {
		counts[key] = new(big.Int).Set(value)
		return
	}
	counts[key].Add(counts[key], value)
}

type pathState struct{ offset, digits, specials int }

type wordMatch struct {
	position, digits, specials int
	paths                      *big.Int
}

type wordWalkState struct {
	node             *wordNode
	digits, specials int
	afterInsertion   bool
}

func (g *Generator) findWordMatches(ctx context.Context, chars []rune, state pathState) ([]wordMatch, error) {
	matches := make([]wordMatch, 0)
	states := map[wordWalkState]*big.Int{{node: g.root}: big.NewInt(1)}
	for position := state.offset; position <= len(chars); position++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(states) == 0 {
			break
		}
		next := make(map[wordWalkState]*big.Int)
		for current, count := range states {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if match := g.advanceWordWalk(chars, position, state, current, count, next); match != nil {
				matches = append(matches, *match)
			}
		}
		states = next
	}
	return matches, nil
}

func (g *Generator) advanceWordWalk(chars []rune, position int, limits pathState, current wordWalkState, count *big.Int, next map[wordWalkState]*big.Int) *wordMatch {
	var match *wordMatch
	if !current.afterInsertion && current.node.terminal {
		match = &wordMatch{position: position, digits: current.digits, specials: current.specials, paths: new(big.Int).Set(count)}
	}
	if position == len(chars) {
		return match
	}
	if child := current.node.children[chars[position]]; child != nil {
		addCount(next, wordWalkState{node: child, digits: current.digits, specials: current.specials}, count)
	}
	canInsert := !current.afterInsertion && current.node != g.root && position+1 < len(chars)
	if canInsert && current.digits < limits.digits && chars[position] >= '0' && chars[position] <= '9' {
		addCount(next, wordWalkState{node: current.node, digits: current.digits + 1, specials: current.specials, afterInsertion: true}, count)
	}
	if canInsert && current.specials < limits.specials && strings.ContainsRune(SpecialCharacters, chars[position]) {
		addCount(next, wordWalkState{node: current.node, digits: current.digits, specials: current.specials + 1, afterInsertion: true}, count)
	}
	return match
}

func (g *Generator) countGenerationPaths(ctx context.Context, password string) (*big.Int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	chars := []rune(password)
	matchCache := make(map[pathState][]wordMatch)
	states := map[pathState]*big.Int{{}: big.NewInt(1)}
	for range g.config.WordCount {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next := make(map[pathState]*big.Int)
		for state, count := range states {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			matchState := pathState{offset: state.offset, digits: g.config.DigitCount - state.digits, specials: g.config.SpecialCount - state.specials}
			matches, ok := matchCache[matchState]
			if !ok {
				var err error
				matches, err = g.findWordMatches(ctx, chars, matchState)
				if err != nil {
					return nil, err
				}
				matchCache[matchState] = matches
			}
			for _, found := range matches {
				nextState := pathState{found.position, state.digits + found.digits, state.specials + found.specials}
				paths := new(big.Int).Mul(count, found.paths)
				addCount(next, nextState, paths)
			}
		}
		states = next
	}
	result := states[pathState{offset: len(chars), digits: g.config.DigitCount, specials: g.config.SpecialCount}]
	if result == nil {
		return new(big.Int), nil
	}
	return new(big.Int).Set(result), nil
}
