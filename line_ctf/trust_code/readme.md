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
