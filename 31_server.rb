require 'webrick'
require_relative 'util'

KEY = random_word.bytes
DELAY = 0.05

def unsafe_compare(string1, string2)
  return false if string1.length != string2.length
  string1.length.times do |i|
    return false if string1[i] != string2[i]
    sleep(DELAY)
  end
  true
end

def verify(buffer, mac)
  unsafe_compare(mac, sha1_hmac(buffer, KEY))
end

def parse_query_string(string)
  string.split('&').map do |part|
    key, value = part.split('=')
    [key.to_sym, value]
  end.to_h
end

server = WEBrick::HTTPServer.new(Port: 9000)

server.mount_proc '/test' do |req, res|
  query = parse_query_string(req.query_string)
  if query[:file] && query[:signature] &&
     verify(query[:file].bytes, query[:signature])
    res.status = 200
  else
    res.status = 500
  end
end

trap('INT') { server.shutdown }
server.start
