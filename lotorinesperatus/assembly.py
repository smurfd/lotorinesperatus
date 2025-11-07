from lotorinesperatus.assembly_arm64_macho import Arm64_macho
from lotorinesperatus.assembly_amd64_elf import Amd64_elf
import binascii


class Assembly:
  def __init__(self, fn, arch='arm64', flavour='arm64', binfmt='macho') -> None:
    self.flavour = flavour
    self.binfmt = binfmt
    self.arch = arch
    self.fn = fn
    if self.arch == 'arm64' and self.flavour == 'arm64' and binfmt == 'macho': self.asm = Arm64_macho(self.fn)
    elif self.arch == 'amd64' and self.flavour == 'amd64' and binfmt == 'elf': self.asm = Amd64_elf(self.fn)
  def bytes2hex(self, b):
    if isinstance(b, list): return [(f'{binascii.hexlify(h).decode():08}') for h in b]
    elif isinstance(b, bytes): st = f'{binascii.hexlify(b).decode()}'; return [st[i:i+8] for i in range(0, len(st), 8)]
  def hex2str(self, h): return ''.join([chr(int(h[i:i+2], 16)) for i in range(0, len(h), 2)]) 


class Format:
  def __init__(self) -> None: pass
  def get_color_red(self, s): return '\033[91m{}\033[00m'.format(s)
  def get_color_green(self, s): return '\033[92m {}\033[00m'.format(s)
  def get_color_yellow(self, s): return '\033[93m {}\033[00m'.format(s)
  def get_color_purple(self, s): return '\033[95m {}\033[00m'.format(s)
  def format_output(self, st):
    ret = ''
    for i,x in enumerate(st.split('\t')):
      if i == 0: r = self.get_color_red(str(x))
      elif i == 1: r = self.get_color_green(str(x))
      elif i == 2: r = self.get_color_yellow(str(x))
      else: r = self.get_color_purple(str(x))
      ret += (r + ' ')
    return ret
  def print(self, st) -> None:
    for line in st.split('\n'): print(self.format_output(line))
