#!/usr/bin/env python3
class LotorInesperatus:
  def __init__(self, fn):
    self.chunks = []
    with open(fn, 'rb') as f:
      while True:
        chunk = f.read(4)
        if not chunk: break
        self.chunks.append(chunk)

  def get(self):
    return self.chunks
