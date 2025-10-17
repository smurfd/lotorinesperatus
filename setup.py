#!/usr/bin/env python3
import setuptools

description = open('README.md', 'r').read()
setuptools.setup(
  name='lotorinesperatus',
  version='0.0.1',
  author='smurfd',
  author_email='smurfd@gmail.com',
  packages=['lotorinesperatus'],
  description='Disassembly, with bagged eyes',
  long_description=description,
  long_description_content_type='text/markdown',
  url='https://github.com/smurfd/lotorinesperatus',
  license='MIT',
  python_requires='>=3.11',
  require={'capstone'},
  extras_require={
    'testing': [
      'pytest',
    ],
    'linting': [
      'ruff',
      'mypy',
      'pre-commit',
    ],
  },
)
