# 676 Notes
## Table of Contents
_________
* [Useful Things to Know](#Useful-Things-to-Know)
* [x86](#x86)
* [pwntools](#pwntools)
* [Radare2](#Radare2)
* [Buffer Overflow](#Buffer-Overflow)
* [Assembly](#Assembly)
* [ROP Chaining](#ROP-Chaining)
* [GOT PLT Linking & Exploiting](#GOT-PLT-Linking-&-Exploiting)
* [String Format Vulnerabilities](#String-Format-Vulnerabilities)

## Useful Things to Know
_________
#### Tmux:
* Start Tmux with `tmux`
* `ctrl + B + %` to split the screen
* `ctrl + B + O` to switch between panes
* Full list of instructions [here](https://tmuxcheatsheet.com/)

## x86
______________________________________________________
#### Registers (e-- is 32-bit, r-- is 64-bit)
| Register | 64-bit | 32-bit | Purpose |
| :--: | :--: | :--: | :--: | 
| Accumulator | rax | eax | I/0 access, arithmetic, interrupt calls |
| Counter | rcx | ecx | Loop counter |
| Data | rdx | edx | I/O port access, arithmetic |
| Base | rbx | ebx | Base pointer for memory access |
| Stack Pointer | rsp | esp | Holds the top address of the stack |
| Stack Base Pointer | rbp | ebp | Hold base address of the stack |
| Source | rsi | esi | String and memory array copying |
| Destination | rdi | edi | String and memory array copying

## pwntools
____________________
* To enter the interactive terminal type `ipython3`
* First line of code should always be `from pwn import *`
* When cracking into an executable: `p = process("filename")`
* When cracking into a remote server: `p = remote("ip", port_number)`
* Use `p.recv()` to show anything that the executable is printing
* Use `p.sendline()` or `p.send()` to send the payload
* Use `elf = ELF("filename")` to get any important information about the executable
    - Use `elf.got` to get the values inside of the GOT

## Radare2
_________
* Look at the assembly of an executable using `r2 -Ad filename`
    - `s function_name` or `s memory_address`
        * usually use `s main`
    - `Vpp` to see the code
    - `:db address` to set a breakpoint
        - `:dc` to continue

## Buffer Overflow
_____________
* This is used to overrwrite existing local variables
* WHEN TO USE: if gets is used to get data in the executable 
* Find the local variable that you want to overwrite using r2 (it will look like `var int64_t var_20h @ rbp-0x20`)
* Add 4 bytes in 32-bit and 8 bytes in 64-bit for return address

## Assembly
_______________
* Perform syscalls using int 0x80
* Full list of syscalls [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)
* eax is the type of syscall
* Arguments go ebx, ecx, edx, esi, edi, ebp in that order

## ROP Chaining
___________________
#### All relevant instructions and the order to use them in:
1. Use `file filename` to see what type of file it is, how it was compiled, and whether it was stripped
    * If file is not stripped:
        * Use `rabin2 -s filename` to see all of the functions and their locations inside of the executable
        * Use `rabin2 -z filename` to see all of the strings and their locations inside of the executable
2. Use `checksec filename` to see possible vulnerabilities
3. Use `r2 -Ad filename` to get any necessary function and argument locations
4. Use ` ROPgadget --binary filename | grep pop` to get a `pop; ret` statement
    * The number of pop statements depends on the number of arguments, 3 args = 3 pops
    
#### Application:
* 32-bit:
    ```python
    from pwn import *
    offset = 44 # it's usually 44, but it might not be
    function_address = ___
    pop_address = ___
    argument = ___
    inject = b"a" * p32(offset) + p32(function_address) + p32(pop_address) + p32(argument)
    ```
* 64-bit:
    ```python
    from pwn import *
    offset = 40 # it's usually 40, but it might not be
    function_address = ___
    pop_address = ___
    argument = ___
    inject = b"a" * p64(offset) + p64(pop_address) + p64(argument) + p64(function_address)
    ```
## GOT PLT Linking & Exploiting
_________
All relevant instructions and the order to use them in:
1. Use `ldd filename` to get the location of libc (will look like `libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6`)

## String Format Vulnerabilities
___
#### When to Use:
* When asked for input type `%p`, if something other than `%p` shows up, there is a printf vulnerability

#### How to Use:
##### 32-bit:
1. Start with `%1$p`, `%2$p`, and continue until you see the hex value for what you input (if you input )
2. Do `inject = p32(target_address)`
3. Increase the size of what gets printed by using `%Sx` where S is the number of spaces to add (x is just the letter x)
4. Write the width of the injection to the target as bytes
    * Assuming N is the argument number:
        * 1 byte: `%N$hhn`
        * 2 bytes: `%N$hn`
        * 4 bytes: `%N$n`
        * 8 bytes: `%N$lln`
* Payload will look like:
```python
from pwn import *
inject = p32(target_address) + b"%Sx" + b"%N$hhn" # S = number of spaces to add, N = argument number
```

##### 64-bit:
