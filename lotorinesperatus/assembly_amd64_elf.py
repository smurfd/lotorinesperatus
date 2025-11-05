# TODO: READ
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://gabi.xinuos.com/v42/elf.pdf
class Amd64_elf:
  def __init__(self, fn):
    self.header = [b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b'']
    self.proghd = [b'', b'', b'', b'', b'', b'', b'', b'']
    self.secthd = [b'', b'', b'', b'', b'', b'', b'', b'', b'', b'']
    hl, ll, sl = self.get_lengths()
    self.fn = fn
    with open(self.fn, 'rb') as f: self.h, self.p, self.s = f.read(hl), f.read(ll) f.read(sl)
  def get_lengths(self): return 64, 72, 65   # header, proghd, secthd
  def get_header(self):              # [::-1] for big endian
    self.header[0] = self.h[0:4]     # Magic number
    self.header[1] = self.h[4:5]     # 32bit or 64bit
    self.header[2] = self.h[5:6]     # Endianess
    self.header[3] = self.h[6:7]     # Version
    self.header[4] = self.h[7:8]     # Target system ABI
    self.header[5] = self.h[8:9]     # ABI version
    self.header[6] = self.h[9:16]    # Padding, should be zeros
    self.header[7] = self.h[16:18]   # Object filetype
    self.header[8] = self.h[18:20]   # Target instruction set arch
    self.header[9] = self.h[20:24]   # Version
    self.header[10] = self.h[24:32]  # Memory address from where execution starts
    self.header[11] = self.h[32:40]  # Memory address for Program offset
    self.header[12] = self.h[40:48]  # Points to the start of the section header table
    self.header[13] = self.h[48:52]  # Flags
    self.header[14] = self.h[52:54]  # This header size, 64 for 64bit
    self.header[15] = self.h[54:56]  # Program header size, 56 for 64bit
    self.header[16] = self.h[56:58]  # Program header number of entries
    self.header[17] = self.h[58:60]  # Section header size, 64 for 64bit
    self.header[18] = self.h[60:62]  # Section header number of entries
    self.header[19] = self.h[62:64]  # Section header index
    return self.header
  def get_header_program(self):
    self.proghd[0] = self.p[0:4]     # Segment type
    self.proghd[1] = self.p[4:8]     # Segment-dependent flags
    self.proghd[2] = self.p[8:16]    # Segment offset in the file image
    self.proghd[3] = self.p[16:24]   # Virtual Address of the segment in memory
    self.proghd[4] = self.p[24:32]   # Segments physical address
    self.proghd[5] = self.p[32:40]   # Size in bytes of the segment in file image
    self.proghd[6] = self.p[56:64]   # Size in bytes of the segment in memory
    self.proghd[7] = self.p[64:72]   # Alignment
    return self.proghd
  def get_header_section(self):
    self.secthd[0] = self.s[0:4]     # Offset to name string 
    self.secthd[1] = self.s[4:8]     # Type of header
    self.secthd[2] = self.s[8:16]    # Flags
    self.secthd[3] = self.s[16:24]   # Virtual address of the section in memory
    self.secthd[4] = self.s[24:32]   # Section offset in the file image
    self.secthd[5] = self.s[32:40]   # Section size in bytes
    self.secthd[6] = self.s[40:44]   # Section index
    self.secthd[7] = self.s[44:48]   # Section information
    self.secthd[8] = self.s[48:56]   # Section alignment
    self.secthd[9] = self.s[56:64]   # Section entry size
    return self.secthd

