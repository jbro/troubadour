package troubadour

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestGeneratePropagatesRandomSourceFailure(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.SpecialCount = 0
	config.MinimumSurprisal = 0
	generator, err := NewGenerator(t.Context(), []string{"cat", "dog"}, config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = generator.generate(t.Context(), errorReader{})
	if err == nil || !strings.Contains(err.Error(), "random source failed") {
		t.Fatalf("error = %v, want random-source failure", err)
	}
}

func TestRandomIndexRejectsOutOfRangeSamples(t *testing.T) {
	t.Parallel()

	random := bytes.NewReader([]byte{0xff, 0x00})
	index, err := randomIndex(random, 10)
	if err != nil {
		t.Fatal(err)
	}
	if index != 0 || random.Len() != 0 {
		t.Fatalf("index = %d, remaining bytes = %d; rejection sampling did not consume both samples", index, random.Len())
	}
}

func TestDictionaryBuilderEnforcesTrieLimit(t *testing.T) {
	t.Parallel()

	builder := dictionaryBuilder{
		prepared:          make([]preparedWord, 0, 1),
		lookup:            make(map[string]struct{}),
		root:              &wordNode{},
		minimumWordLength: maxWordLength,
		trieNodes:         maxTrieNodes,
	}
	if err := builder.add("cat"); err == nil || !strings.Contains(err.Error(), "trie must not exceed") {
		t.Fatalf("error = %v, want trie-node limit error", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("random source failed")
}
