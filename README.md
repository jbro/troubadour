# troubadour
A small script for generating memorable word-based passwords using cryptographically secure randomness.

    ./troubadour.rb -h
    Usage: ./troubadour.rb [options]
        -m, --min_length=N               Minimum length of word to select
        -M, --max_length=N               Maximum length of a word to select
        -n, --words=N                    Number of words to select
        -c, --count=N                    Number of passwords to generate
        -d, --digits=N                   Number of digits to insert
        -s, --special_chars=N            Number of special characters to insert
        -t, --timeout=SECONDS             Collision calculation timeout per password
        -l, --word_list=FILE             Word list to select words from
        -E, --exclude=REGEXP             Regular expression for excluding words
        -h, --help                       Prints this help

`-d` inserts exactly the requested number of digits. `-s` inserts exactly the
requested number of ASCII punctuation characters; digits and spaces are not
part of this special-character set. The entropy value estimates the choices
made by the generator and assumes the word selections produce distinct
passwords.

The naive search-space value assumes an attacker tests every possible string
character by character. It is not the password's generation entropy.
Collision-adjusted surprisal counts every valid generation path for the
password, including ambiguous word boundaries and inserted characters that
could belong to a word. This exact calculation has a five-second deadline per
password by default, configurable with `--timeout`.
