# TODO: Read
# https://en.wikipedia.org/wiki/Mach-O
# https://medium.com/@andrewss112/reverse-engineering-mach-o-arm64-d33f6373ed85
# https://valsamaras.medium.com/arm-64-assembly-series-basic-definitions-and-registers-ec8cc1334e40
# https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.html
# https://formats.kaitai.io/mach_o/python.html
# https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/
# https://yossarian.net/res/pub/macho-internals/macho-internals.pdf
class Arm64_macho:
  def __init__(self, fn):
    self.header, self.loader, self.data, self.fn = [], [], [], fn
    hl, ll = self.get_lengths()
    with open(self.fn, 'rb') as f: self.h, self.l, self.d = f.read(hl), f.read(ll), f.read()
  def get_lengths(self): return 32, 72             # header, loader
  def get_header(self):                            # [::-1] for big endian
    self.header.append(self.h[0:4])                # Magic number
    self.header.append(self.h[4:8])                # CPU type
    self.header.append(self.h[8:12])               # CPU subtype
    self.header.append(self.h[12:16])              # Filetype
    self.header.append(self.h[16:20])              # Number of load commands
    self.header.append(self.h[20:24])              # Size of load commands
    self.header.append(self.h[24:28])              # Flags
    self.header.append(self.h[28:32])              # Reserved. 64bit only
    return self.header
  def get_loader(self):
    self.loader.append(self.l[0:4])                # Command type
    self.loader.append(self.l[4:8])                # Command size
    self.loader.append(self.l[8:24])               # Segment name
    self.loader.append(self.l[24:32])              # Address
    self.loader.append(self.l[32:40])              # Address size
    self.loader.append(self.l[40:48])              # File offset
    self.loader.append(self.l[48:56])              # Size (bytes from file offset)
    self.loader.append(self.l[56:60])              # Maximum virtual memory protection
    self.loader.append(self.l[60:64])              # Initial virtual memory protection
    self.loader.append(self.l[64:68])              # Number of sections
    self.loader.append(self.l[68:72])              # Flags32
    return self.loader
  def get_data(self):
    self.data = self.d
    return self.data

"""
>>> s = "68656c6c6f20776f726c64"
>>> res = ''.join([chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2)])
>>> res
'hello world'


b = [b'\xcf\xfa\xed\xfe', b'\x0c\x00\x00\x01', b'\x00\x00\x00\x00', b'\x02\x00\x00\x00', b'\x11\x00\x00\x00', b' \x04\x00\x00', b'\x85\x00 \x00', b'\x00\x00\x00\x00', b'\x19\x00\x00\x00', b'H\x00\x00\x00', b'__PAGEZERO\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x01\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00']
>>> for b1 in b:
...     print(binascii.hexlify(b1))
"""
