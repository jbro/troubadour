#!/usr/bin/env ruby
require 'optparse'

WILDCHARS = (32..126).map { |n| n.chr }.reject { |c| c =~ /[a-zA-Z]/ }

criteria = {
  minWordLength: 3,
  maxWordLength: 8,
  wordCount:     3,
  wildCharCount: 1,
  wordList:      '/usr/share/dict/words',
  excludeExp:    /^$/
}

op = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('-m', '--min_length=n', 'Minimum length of word to select') do |a|
    raise OptionParser::ParseError, "n must be greater than 1" if a.to_i < 2
    criteria[:minWordLength] = a.to_i
  end

  opts.on('-M', '--max_length=n', 'Maximum length of a word to select') do |a|
    raise OptionParser::ParseError, "n must be greater than 1" if a.to_i < 2
    criteria[:maxWordLength] = a.to_i
  end

  opts.on('-n', '--words=n', 'Number of words to select') do |a|
    criteria[:wordCount] = a.to_i
  end

  opts.on('-w', '--wild_chars=n', 'Number of wild chars to randomly insert') do |a|
    criteria[:wildCharCount] = a.to_i
  end

  opts.on('-l', "--word_list=FILE", "Word list to select words from") do |a|
    raise OptionParser::ParseError, "file does not exist" unless File.file?(a)
    criteria[:wordList] = a
  end

  opts.on('-E', "--exclude=REGEXP", "Regular expression for excluding words") do |a|
    criteria[:excludeExp] = Regexp.new(a)
  end

  opts.on('-h', '--help', "Prints this help") do
    puts opts
    exit
  end
end

begin
  op.parse!
rescue OptionParser::ParseError => e
  puts e
  puts op
  exit 1
end

lines = File.readlines(criteria[:wordList]).select { |l|
  l = l.chomp
  l.length >= criteria[:minWordLength] &&
    l.length <= criteria[:maxWordLength]
}.reject { |l| l.chomp =~ criteria[:excludeExp]}

words = []
1.upto(criteria[:wordCount]) do |i|
  words << lines.sample.chomp
end

puts "Words:       #{words.join(' ')}"

wildChars = []
1.upto(criteria[:wildCharCount]) do |i|
  wc = WILDCHARS.sample
  wildChars << wc
  w = words.sample
  i = words.find_index(w)
  words[i] = w.insert(rand(1...w.length), wc)
end

puts "Wildchar(s): #{wildChars.join('')}"

password = words.join('')

puts "Password:    #{password}"
puts "Length:      #{password.length}"

wordCount = lines.length
wordCharCount = lines.map { |l| l.chomp.chars.to_a.uniq }.join('').chars.to_a.uniq.length + WILDCHARS.length


puts "Entropy:     #{Math.log2(wordCharCount ** password.length).round(2)} (#{Math.log2(wordCount ** criteria[:wordCount]).round(2)})"
