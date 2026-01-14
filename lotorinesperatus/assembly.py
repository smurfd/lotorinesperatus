#!/usr/bin/env python3
# Auth: smurfd, 2025; 2 space indent; 150 width;                                                                                                    #
# ------------------------------------------------------------------------------------------------------------------------------------------------- #
from lotorinesperatus.assembly_arm64_macho import Arm64_macho
from lotorinesperatus.assembly_amd64_elf import Amd64_elf
from typing import List, Tuple, Literal
import binascii, csv


class Assembly:
  def __init__(self, fn, arch='arm64', flavour='arm64', binfmt='macho') -> None:
    self.flavour, self.binfmt, self.arch, self.fn = flavour, binfmt, arch, fn
    if self.arch == 'arm64' and self.flavour == 'arm64' and binfmt == 'macho': self.asm = Arm64_macho(self.fn)
    elif self.arch == 'amd64' and self.flavour == 'amd64' and binfmt == 'elf': self.asm = Amd64_elf(self.fn)
  def bytes2hex(self, b) -> List:
    if isinstance(b, list): return [(f'{binascii.hexlify(h).decode():08}') for h in b]
    elif isinstance(b, bytes): st = f'{binascii.hexlify(b).decode()}'; return [st[i:i + 8] for i in range(0, len(st), 8)]
  def hex2str(self, h) -> Literal: return ''.join([(h[i:i + 2]).decode('latin-1') for i in range(0, len(h), 2)])
  def print_hex(self, h) -> None:
    for i in range(0, len(h), 8): print(f'{(i * 4):08} ' + ' '.join([f'{num:08}' for num in h[i:i + 8]]))


class Format:
  def __init__(self) -> None: pass
  def get_color_red(self, s) -> bytes: return '\033[91m{}\033[00m'.format(s)
  def get_color_green(self, s) -> bytes: return '\033[92m {}\033[00m'.format(s)
  def get_color_yellow(self, s) -> bytes: return '\033[93m {}\033[00m'.format(s)
  def get_color_purple(self, s) -> bytes: return '\033[95m {}\033[00m'.format(s)
  def format_output(self, st) -> Literal: return ' '.join([self.get_color_red(str(x)) if i == 0 else self.get_color_green(str(x))
    if i == 1 else self.get_color_yellow(str(x)) if i == 2 else self.get_color_purple(str(x)) for i, x in enumerate(st.split('\t'))])
  def print(self, st) -> None: [print(f'{self.format_output(line)}') for line in st.split('\n')]


class Objdump:
  def __init__(self, fn) -> None: self.fn = fn; self.ctx = []
  def get(self) -> Literal:
    with open(self.fn, newline='') as f:
      self.r = csv.reader(f, delimiter='\t')
      for x in self.r:
        if x[1:]: self.ctx.append(x[1:])
    return self.ctx
