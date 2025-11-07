# TODO: READ
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://gabi.xinuos.com/v42/elf.pdf
class Amd64_elf:
  def __init__(self, fn):
    self.header, self.proghd, self.secthd, self.data, self.fn = [], [], [], [], fn
    hl, ll, sl = self.get_lengths()
    with open(self.fn, 'rb') as f: self.h, self.p, self.s, self.d = f.read(hl), f.read(ll), f.read(sl), f.read()
  def get_lengths(self): return 64, 72, 65         # header, proghd, secthd
  def get_header(self):                            # [::-1] for big endian
    self.header.append(self.h[0:4])                # Magic number
    self.header.append(self.h[4:5])                # 32bit or 64bit
    self.header.append(self.h[5:6])                # Endianess
    self.header.append(self.h[6:7])                # Version
    self.header.append(self.h[7:8])                # Target system ABI
    self.header.append(self.h[8:9])                # ABI version
    self.header.append(self.h[9:16])               # Padding, should be zeros
    self.header.append(self.h[16:18])              # Object filetype
    self.header.append(self.h[18:20])              # Target instruction set arch
    self.header.append(self.h[20:24])              # Version
    self.header.append(self.h[24:32])              # Memory address from where execution starts
    self.header.append(self.h[32:40])              # Memory address for Program offset
    self.header.append(self.h[40:48])              # Points to the start of the section header table
    self.header.append(self.h[48:52])              # Flags
    self.header.append(self.h[52:54])              # This header size, 64 for 64bit
    self.header.append(self.h[54:56])              # Program header size, 56 for 64bit
    self.header.append(self.h[56:58])              # Program header number of entries
    self.header.append(self.h[58:60])              # Section header size, 64 for 64bit
    self.header.append(self.h[60:62])              # Section header number of entries
    self.header.append(self.h[62:64])              # Section header index
    return self.header
  def get_header_program(self):
    self.proghd.append(self.p[0:4])                # Segment type
    self.proghd.append(self.p[4:8])                # Segment-dependent flags
    self.proghd.append(self.p[8:16])               # Segment offset in the file image
    self.proghd.append(self.p[16:24])              # Virtual Address of the segment in memory
    self.proghd.append(self.p[24:32])              # Segments physical address
    self.proghd.append(self.p[32:40])              # Size in bytes of the segment in file image
    self.proghd.append(self.p[56:64])              # Size in bytes of the segment in memory
    self.proghd.append(self.p[64:72])              # Alignment
    return self.proghd
  def get_header_section(self):
    self.secthd.append(self.s[0:4])                # Offset to name string 
    self.secthd.append(self.s[4:8])                # Type of header
    self.secthd.append(self.s[8:16])               # Flags
    self.secthd.append(self.s[16:24])              # Virtual address of the section in memory
    self.secthd.append(self.s[24:32])              # Section offset in the file image
    self.secthd.append(self.s[32:40])              # Section size in bytes
    self.secthd.append(self.s[40:44])              # Section index
    self.secthd.append(self.s[44:48])              # Section information
    self.secthd.append(self.s[48:56])              # Section alignment
    self.secthd.append(self.s[56:64])              # Section entry size
    return self.secthd
  def get_data(self):
    self.data = self.d
    return self.data
