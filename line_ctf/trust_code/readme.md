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



