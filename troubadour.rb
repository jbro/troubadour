#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'securerandom'
require 'timeout'

DIGITS = ('0'..'9').to_a.freeze
SPECIAL_CHARS = (33..126).map(&:chr).reject { |char| char.match?(/[a-zA-Z0-9]/) }.freeze

def log2_combination(total, selected)
  return 0.0 if selected.zero? || total == selected

  (Math.lgamma(total + 1).first - Math.lgamma(selected + 1).first -
    Math.lgamma(total - selected + 1).first) / Math.log(2)
end

# Count every word-boundary and insertion interpretation that produces the password.
def count_generation_paths(password, word_lookup, config)
  characters = password.chars
  match_cache = {}

  matches_from = lambda do |offset, remaining_digits, remaining_specials|
    cache_key = [offset, remaining_digits, remaining_specials]
    next match_cache[cache_key] if match_cache.key?(cache_key)

    matches = []
    walk = nil
    walk = lambda do |position, word, digits, specials, after_insertion|
      if !after_insertion && word.length >= config[:min_word_length] && word_lookup.key?(word)
        matches << [position, digits, specials]
      end

      next if position >= characters.length || word.length >= config[:max_word_length]

      char = characters[position]
      walk.call(position + 1, word + char, digits, specials, false)

      can_insert = !after_insertion && !word.empty? && position + 1 < characters.length
      if can_insert && digits < remaining_digits && DIGITS.include?(char)
        walk.call(position + 1, word, digits + 1, specials, true)
      end
      if can_insert && specials < remaining_specials && SPECIAL_CHARS.include?(char)
        walk.call(position + 1, word, digits, specials + 1, true)
      end
    end

    walk.call(offset, '', 0, 0, false)
    match_cache[cache_key] = matches
  end

  states = { [0, 0, 0] => 1 }
  config[:word_count].times do
    next_states = Hash.new(0)
    states.each do |(offset, digits, specials), path_count|
      remaining_digits = config[:digit_count] - digits
      remaining_specials = config[:special_count] - specials
      matches_from.call(offset, remaining_digits, remaining_specials).each do |position, added_digits, added_specials|
        key = [position, digits + added_digits, specials + added_specials]
        next_states[key] += path_count
      end
    end
    states = next_states
  end

  states.fetch([characters.length, config[:digit_count], config[:special_count]], 0)
end

config = {
  min_word_length: 3,
  max_word_length: 8,
  word_count: 3,
  password_count: 1,
  digit_count: 0,
  special_count: 1,
  calculation_timeout: 5.0,
  word_list: '/usr/share/dict/words',
  exclude_regex: /^$/
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('-m', '--min_length=N', Integer, 'Minimum length of word to select') do |value|
    raise OptionParser::InvalidArgument, 'N must be greater than 1' if value < 2
    config[:min_word_length] = value
  end

  opts.on('-M', '--max_length=N', Integer, 'Maximum length of a word to select') do |value|
    raise OptionParser::InvalidArgument, 'N must be greater than 1' if value < 2
    config[:max_word_length] = value
  end

  opts.on('-n', '--words=N', Integer, 'Number of words to select') do |value|
    raise OptionParser::InvalidArgument, 'N must be greater than 0' if value < 1
    config[:word_count] = value
  end

  opts.on('-c', '--count=N', Integer, 'Number of passwords to generate') do |value|
    raise OptionParser::InvalidArgument, 'N must be greater than 0' if value < 1
    config[:password_count] = value
  end

  opts.on('-d', '--digits=N', Integer, 'Number of digits to insert') do |value|
    raise OptionParser::InvalidArgument, 'N must not be negative' if value.negative?
    config[:digit_count] = value
  end

  opts.on('-s', '--special_chars=N', Integer, 'Number of special characters to insert') do |value|
    raise OptionParser::InvalidArgument, 'N must not be negative' if value.negative?
    config[:special_count] = value
  end

  opts.on('-t', '--timeout=SECONDS', Float, 'Collision calculation timeout per password') do |value|
    raise OptionParser::InvalidArgument, 'SECONDS must be greater than 0' unless value.positive?
    config[:calculation_timeout] = value
  end

  opts.on('-l', '--word_list=FILE', 'Word list to select words from') do |path|
    path = File.expand_path(path)
    raise OptionParser::InvalidArgument, 'file does not exist' unless File.file?(path)
    config[:word_list] = path
  end

  opts.on('-E', '--exclude=REGEXP', 'Regular expression for excluding words') do |value|
    config[:exclude_regex] = Regexp.new(value)
  end

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end

begin
  parser.parse!
  if config[:min_word_length] > config[:max_word_length]
    raise OptionParser::InvalidArgument, 'minimum length must not exceed maximum length'
  end
rescue OptionParser::ParseError, RegexpError => e
  puts e
  puts parser
  exit 1
end

lines = File.readlines(config[:word_list], chomp: true).select do |line|
  line.length.between?(config[:min_word_length], config[:max_word_length])
end.reject { |line| line.match?(config[:exclude_regex]) }.uniq

if lines.empty?
  warn 'No words match the requested criteria'
  exit 1
end

character_alphabet = {}
lines.each { |line| line.each_char { |char| character_alphabet[char] = true } }
DIGITS.each { |char| character_alphabet[char] = true } if config[:digit_count].positive?
SPECIAL_CHARS.each { |char| character_alphabet[char] = true } if config[:special_count].positive?
word_lookup = lines.each_with_object({}) { |word, lookup| lookup[word] = true }

passwords = Array.new(config[:password_count]) do
  words = Array.new(config[:word_count]) do
    lines[SecureRandom.random_number(lines.length)]
  end

  available_positions = words.each_with_index.flat_map do |word, word_index|
    (1...word.length).map { |char_index| [word_index, char_index] }
  end

  inserted_count = config[:digit_count] + config[:special_count]
  if inserted_count > available_positions.length
    warn "Cannot insert #{inserted_count} characters into #{available_positions.length} available positions"
    exit 1
  end

  insertions = Array.new(words.length) { {} }
  digits = Array.new(config[:digit_count]) do
    DIGITS[SecureRandom.random_number(DIGITS.length)]
  end
  specials = Array.new(config[:special_count]) do
    SPECIAL_CHARS[SecureRandom.random_number(SPECIAL_CHARS.length)]
  end

  (digits + specials).each do |char|
    word_index, char_index = available_positions.delete_at(SecureRandom.random_number(available_positions.length))
    insertions[word_index][char_index] = char
  end

  decorated_words = words.each_with_index.map do |word, word_index|
    word.chars.each_with_index.map do |char, char_index|
      "#{insertions[word_index][char_index]}#{char}"
    end.join
  end

  position_count = words.sum { |word| word.length - 1 }
  entropy = config[:word_count] * Math.log2(lines.length)
  entropy += log2_combination(position_count, config[:digit_count])
  entropy += log2_combination(position_count - config[:digit_count], config[:special_count])
  entropy += config[:digit_count] * Math.log2(DIGITS.length)
  entropy += config[:special_count] * Math.log2(SPECIAL_CHARS.length)
  password = decorated_words.join

  path_count = begin
    Timeout.timeout(config[:calculation_timeout]) do
      count_generation_paths(password, word_lookup, config)
    end
  rescue Timeout::Error
    nil
  end

  if path_count&.zero?
    warn 'Unable to find the generation path for a generated password'
    exit 1
  end

  {
    words: words,
    digits: digits,
    specials: specials,
    password: password,
    entropy: entropy,
    naive_space: password.length * Math.log2(character_alphabet.length),
    path_count: path_count,
    surprisal: path_count && entropy - Math.log2(path_count)
  }
end

passwords.each_with_index do |result, index|
  puts if index.positive?
  words = result[:words].join(' ')
  words = "\e[1m#{words}\e[0m" if $stdout.tty?
  puts "Words:       #{words}"
  puts "Digit(s):    #{result[:digits].join}"
  puts "Special(s):  #{result[:specials].join}"
  puts "Password:    #{result[:password]}"
  puts "Length:      #{result[:password].length}"
  puts "Naive space: #{result[:naive_space].round(2)} bits (character-by-character search)"
  if result[:path_count]
    path_label = result[:path_count] == 1 ? 'path' : 'paths'
    puts "Entropy:     collision-adjusted #{result[:surprisal].round(2)} bits | " \
         "generation #{result[:entropy].round(2)} bits | " \
         "#{result[:path_count]} valid #{path_label}"
  else
    timeout = format('%g', config[:calculation_timeout])
    puts "Entropy:     collision-adjusted unavailable | " \
         "generation #{result[:entropy].round(2)} bits | " \
         "path count timed out after #{timeout} seconds"
  end
end
