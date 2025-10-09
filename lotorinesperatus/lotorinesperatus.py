#!/usr/bin/env python3
class LotorInesperatus:
  def __init__(self, fn):
    with open(fn, 'rb') as f:
      while True:
        chunk = f.read(20)
        if not chunk: break
        print(f'[{chunk}]')
