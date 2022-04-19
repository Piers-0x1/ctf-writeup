# **Lambang**

## Description
> Lambang is a Pro Hacker guy he made this challenge to test you.  
author: Linz#0417  
nc lambang.crewctf-2022.crewc.tf 1337  

```console
┌──(kali㉿kali)-[~/Desktop/pwn/crew/lambang]
└─$ checksec mynote_patched
[*] '/home/kali/Desktop/pwn/crew/lambang/mynote_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
                                                                                            
┌──(kali㉿kali)-[~/Desktop/pwn/crew/lambang]
└─$ ./mynote_patched
1. Alloc
2. Show
3. Move
4. Copy
> 
```  

## Reversing  
We have 4 options: Allocate, Show, Move and Copy. They do exactly what they imply  

```c
void alloc(void)

{
  uint uVar1;
  uint uVar2;
  void *pvVar3;
  
  printf("Index: ");
  uVar1 = getint();
  if (6 < uVar1) {
    error("Invalid index");
  }
  printf("Size: ");
  uVar2 = getint();
  if ((uVar2 == 0) || (0x70 < uVar2)) {
    error("Invalid size");
  }
  pvVar3 = malloc((ulong)uVar2);
  *(void **)(notes + (ulong)uVar1 * 0x10) = pvVar3;
  *(uint *)(notes + (ulong)uVar1 * 0x10 + 8) = uVar2;
  printf("Content: ");
  getnline(*(undefined8 *)(notes + (ulong)uVar1 * 0x10),uVar2);
  return;
}
```  
There are 7 indexes where we can store the address of the chunk we allocated. We can have the maximum size of `0x70` bytes and we are allowed to write into those chunks.  
`getint()` does return a number larger than integer, but I could not manage to find a way to exploit that.  

```c
void show(void)

{
  uint uVar1;
  
  printf("Index: ");
  uVar1 = getint();
  if ((6 < uVar1) || (*(long *)(notes + (ulong)uVar1 * 0x10) == 0)) {
    error("Invalid index");
  }
  puts(*(char **)(notes + (ulong)uVar1 * 0x10));
  return;
} 
```  
`show()` shows the content of the chunk we allocated  
  
`copy()` has 2 functionality both: move and copy  

```c
int copy(EVP_PKEY_CTX *dst,EVP_PKEY_CTX *src)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  void *local_10;
  
  printf("Index (src): ");
  uVar2 = getint();
  if ((6 < uVar2) || (*(long *)(notes + (ulong)uVar2 * 0x10) == 0)) {
    error("Invalid index");
  }
  printf("Index (dest): ");
  uVar3 = getint();
  if (6 < uVar3) {
    error("Invalid index");
  }
  local_10 = (void *)0x0;
  if (*(long *)(notes + (ulong)uVar3 * 0x10) == 0) {
    local_10 = malloc((ulong)*(uint *)(notes + (ulong)uVar2 * 0x10 + 8));
  }
  else if (*(uint *)(notes + (ulong)uVar3 * 0x10 + 8) < *(uint *)(notes + (ulong)uVar2 * 0x10 + 8) )
  {
    error("No enough space");
  }
  else {
    local_10 = *(void **)(notes + (ulong)uVar3 * 0x10);
  }
  memcpy(local_10,*(void **)(notes + (ulong)uVar2 * 0x10),
         (ulong)*(uint *)(notes + (ulong)uVar2 * 0x10 + 8));
  if ((char)dst != '\0') {
    free(*(void **)(notes + (ulong)uVar2 * 0x10));
    *(undefined8 *)(notes + (ulong)uVar2 * 0x10) = 0;
  }
  *(void **)(notes + (ulong)uVar3 * 0x10) = local_10;
  iVar1 = *(int *)(notes + (ulong)uVar2 * 0x10 + 8);
  *(int *)(notes + (ulong)uVar3 * 0x10 + 8) = iVar1;
  return iVar1;
}
```  

The function does check the index, the size, and the address saved in those 7 indexes carefully.  
It works somewhat like this:  
Check address stored at `src` index != null  
--> Check address stored at `des` index, if null malloc a chunk, if not compare the size between `src` and des ( make sure that size in `des` is enough to copy from `src` to `des`)  
--> Copy content from `src` to `des`  
--> If it's a `move` then free the chunk at `src` and set the address stored at `src` index to 0 (prevent use-after-free)  
--> Set address at `des` index to itself (or the address provided by malloc() ), set size to `src` size  

## Exploitation  
There was a UAF bug in `copy()`, particularly in the last 2 steps:  
--> If it's a `move` then free the chunk at `src` and set the address stored at `src` index to 0 (prevent use-after-free)  
--> Set address at `des` index to itself (or the address provided by malloc() ), set size to `src` size  
The problems is when we `move` to itself. The chunk is freed, the address is set to 0 but after that, the address at `des` get set. But `src` = `des`, thus we have a UAF.  
With this UAF, we can `show()` what stored in that chunk, and `copy()` to write to that chunk, after it was freed.  

```console
┌──(kali㉿kali)-[~/Desktop/pwn/crew/lambang]
└─$ ./mynote_patched
1. Alloc
2. Show
3. Move
4. Copy
> 1
Index: 0
Size: 10
Content: AAAA
1. Alloc
2. Show
3. Move
4. Copy
> 3
Index (src): 0
Index (dest): 0
1. Alloc
2. Show
3. Move
4. Copy
> 2
Index: 0
�p^X
1. Alloc
2. Show
3. Move
4. Copy
> 
```  
```console  
0x555555558060 <notes>: 0x000055555555a2a0      0x000000000000000a
0x555555558070 <notes+16>:      0x0000000000000000      0x0000000000000000
0x555555558080 <notes+32>:      0x0000000000000000      0x0000000000000000
0x555555558090 <notes+48>:      0x0000000000000000      0x0000000000000000
0x5555555580a0 <notes+64>:      0x0000000000000000      0x0000000000000000
```  
The address is still there after freed  
```console
gef➤  x/10gx 0x000055555555a2a0 - 0x10
0x55555555a290: 0x0000000000000000      0x0000000000000021
0x55555555a2a0: 0x000000055555555a      0x000055555555a010
0x55555555a2b0: 0x0000000000000000      0x0000000000020d51
```  
Now we can try to overwrite this freed chunk, which is a tcache bin. We can try tcache poisoning, overwrite the fd pointer at `0x55555555a2a0`. But because this was glibc 2.32, there is an additional mitigation, which is safe-linking.  
You can read more about it here: https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/  
In short,it protects the fd pointer by signing the address with heap address. Because heap address is affted by ASLR, we thus have to leak the heap address before we can overwrite the fd pointer, or else the address we overwrite will be invalid without the signing.  
The formula for masking: P' = P ^ (L >> 12)  
                         P' : the masked address  
                         P  : the original address  
                         L  : the heap address where it's stored at  
                         
When there is only one chunk in tcache bin, P = 0, do the masked address is simply heap address shift left by 12 bit.  
So when we `show()` at address `0x55555555a2a0` it simply prints out the heap address for us `0x000000055555555a`. And we can shift right by 12 bit to get the original heap base address, defeating the aslr, and thus safe-linking.  

### Infoleak  





