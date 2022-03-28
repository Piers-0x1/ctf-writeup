# *Trust Code**

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

