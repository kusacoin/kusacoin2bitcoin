import sys
import hashlib

base58char = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def prenum(s, p):
  c = 0
  while c<len(s) and s[c]==p:
    c += 1
  return c

def base58dec(b):
  d = 0
  for t in b:
    d = d*58 + base58char.index(t)
  d = "%x"%d
  if len(d)%2!=0:
    d = "0"+d
  d = d.decode("hex")
  return "\x00"*prenum(b,"1") + d

def base58enc(d):
  t = int(d.encode("hex"), 16)
  b = ""
  while t>0:
    b += base58char[t%58]
    t /= 58
  return "1"*prenum(d,"\x00") + b[::-1]

def check(d):
  return hashlib.sha256(hashlib.sha256(d).digest()).digest()[:4]

if len(sys.argv)!=2:
  print "python address.py base58address"
  exit(1)

addr = base58dec(sys.argv[1])
if addr[-4:]!=check(addr[:-4]):
  print "invalid address"
  exit(1)

prefix = [
  ("\xc8\x62\x0b\x94", "\x00"),
  ("\x30\x9b\x42\xa4", "\x05"),
  ("\x9e\xa1\xc1\x0a", "\x80"),
  ("\xd3\xd3\x30\xc0", "\x04\x88\xb2\x1e"),
  ("\x8d\xc9\x87\x10", "\x04\x88\xad\xe4"),
  ("\x31\xfb\x8d\xdb", "\x6f"),
  ("\xce\x76\xfd\xf4", "\xc4"),
  ("\xc8\xe3\xc1\x93", "\xef"),
  ("\x37\x86\xa4\xcc", "\x04\x35\x87\xcf"),
  ("\xfc\xb8\x01\xa0", "\x04\x35\x83\x94"),
]

rep = False
for p in prefix:
  if addr.startswith(p[0]):
    addr = p[1] + addr[len(p[0]):]
    rep = True
    break
if not rep:
  print "invalid address"

print base58enc(addr[:-4]+check(addr[:-4]))
