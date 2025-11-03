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
    self.header = [b'', b'', b'', b'', b'', b'', b'', b'']
    self.loader = [b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'']
    hl, ll = self.get_lengths()
    self.fn = fn
    with open(self.fn, 'rb') as f:
      self.h = f.read(hl)
      self.l = f.read(ll)
  def get_lengths(self): return 32, 72   # header, loader
  def get_header(self):             # [::-1] for big endian
    self.header[0] = self.h[0:4]    # Magic number
    self.header[1] = self.h[4:8]    # CPU type
    self.header[2] = self.h[8:12]   # CPU subtype
    self.header[3] = self.h[12:16]  # Filetype
    self.header[4] = self.h[16:20]  # Number of load commands
    self.header[5] = self.h[20:24]  # Size of load commands
    self.header[6] = self.h[24:28]  # Flags
    self.header[7] = self.h[28:32]  # Reserved. 64bit only
    return self.header
  def get_loader(self):
    self.loader[0] = self.l[0:4]    # Command type
    self.loader[1] = self.l[4:8]    # Command size
    self.loader[2] = self.l[8:24]   # Segment name
    self.loader[3] = self.l[24:32]  # Address
    self.loader[4] = self.l[32:40]  # Address size
    self.loader[5] = self.l[40:48]  # File offset
    self.loader[6] = self.l[48:56]  # Size (bytes from file offset)
    self.loader[7] = self.l[56:60]  # Maximum virtual memory protection
    self.loader[8] = self.l[60:64]  # Initial virtual memory protection
    self.loader[9] = self.l[64:68]  # Number of sections
    self.loader[10]= self.l[68:72]  # Flags32
    return self.loader

