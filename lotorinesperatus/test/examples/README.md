hello.c                   - example code
hello_amd64_elf.bin       - compiled on a amd64 elf system: gcc hello.c
hello_amd64_elf.objdump   - dissasembled via objdump -d
hello_arm64_macho.bin     - compiled on a arm64 macho system: gcc hello.c
hello_arm64_macho.objdump - dissasembled via objdump -d

func.c                    - example code
func_amd64_elf.bin        - compiled on a amd64 elf system: gcc hello.c
func_amd64_elf.objdump    - dissasembled via objdump -d
func_arm64_macho.bin      - compiled on a arm64 macho system: gcc hello.c
func_arm64_macho.objdump  - dissasembled via objdump -d
                          - for macho, you can 'otool -tvV file.bin'
