# troubadour
A small script for generating easy to remember wordbased passwords, which are still secure.

    ./troubadour.rb -h
    Usage: ./troubadour.rb [options]
        -m, --min_length=n               Minimum length of word to select
        -M, --max_length=n               Maximum length of a word to select
        -n, --words=n                    Number of words to select
        -w, --wild_chars=n               Number of wild chars to randomly insert
        -l, --word_list=FILE             Word list to select words from
        -E, --exclude=REGEXP             Regular expression for excluding words
        -h, --help                       Prints this help

# Examples

    ./troubadour.rb
    Words:       gingery magnet lammas
    Wildchar(s): "
    Password:    gi"ngerymagnetlammas
    Length:      20
    Entropy:     131.4 (49.3)

    ./troubadour.rb -n 5
    Words:       leadenly primrose filchery sandclub netful
    Wildchar(s): `
    Password:    leadenlyprimrosefilcherysandclu`bnetful
    Length:      39
    Entropy:     256.22 (82.17)

