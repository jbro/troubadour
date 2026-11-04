#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'securerandom'

DIGITS = ('0'..'9').to_a.freeze
SPECIAL_CHARS = (33..126).map(&:chr).reject { |char| char.match?(/[a-zA-Z0-9]/) }.freeze

def log2_combination(total, selected)
  return 0.0 if selected.zero? || total == selected

  (Math.lgamma(total + 1).first - Math.lgamma(selected + 1).first -
    Math.lgamma(total - selected + 1).first) / Math.log(2)
end

config = {
  min_word_length: 3,
  max_word_length: 8,
  word_count: 3,
  password_count: 1,
  digit_count: 0,
  special_count: 1,
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

  opts.on('-l', '--word_list=FILE', 'Word list to select words from') do |path|
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

  {
    words: words,
    digits: digits,
    specials: specials,
    password: decorated_words.join,
    entropy: entropy
  }
end

passwords.each_with_index do |result, index|
  puts if index.positive?
  puts "Words:       #{result[:words].join(' ')}"
  puts "Digit(s):    #{result[:digits].join}"
  puts "Special(s):  #{result[:specials].join}"
  puts "Password:    #{result[:password]}"
  puts "Length:      #{result[:password].length}"
  puts "Entropy:     #{result[:entropy].round(2)} bits (estimated)"
end
