# 676 Notes
## Table of Contents
_________
* [Useful Things to Know](#Useful-Things-to-Know)
* [x86 & Assembly](#x86-&-Assembly)
* [pwntools](#pwntools)
* [Radare2](#Radare2)
* [Buffer Overflow](#Buffer-Overflow)
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

#### Code Snippets:
* Convert from hex bytes to int (b"0x" -> int)
```python
import re
num = int(re.findall(b"([0-9a-f]{6,16})", string)[0], 16)
```

#### Finding Offsets:
* To manually find the offset it is best to run `python -c "print(b"a" * 32)" | filename` starting at 32 and incrementing by 8 until you get a segfault
* After getting a segfault run `dmesg` to see what the output looks like
* The output should be `0x00000000` and if it isn't, decrement the offset by 1 or 2 until it is `0x00000000`

## x86 & Assembly
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

#### Instructions
* Parameters: reg- register, mem- memory address, any- reg or mem
* Full list at the [x86 Assembly Guide](https://flint.cs.yale.edu/cs421/papers/x86-asm/asm.html)
| Name | Example | Description |
| :--: | :-----: | :---------: |
| Move | mov {any}, {any} | Copy data from the first operand and paste the data into the second operand |
| Push | push {any} | Pushes operand to the top of the stack (Max of 4 / 8 bytes at a time depending on 32-bit or 64-bit) |
| Pop | pop {any} | Removes top 4 / 8 bytes from the stack and puts puts it in the operand |
| Load Effective Address | lea {mem}, {reg} | Places address of first operand onto the register specified by second operand |

#### System Calls
* Perform syscalls using `int 0x80` in 32-bit and `syscall` in 64-bit
* Full list of syscalls [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit)
* eax is the type of syscall
* Arguments go ebx, ecx, edx, esi, edi, ebp in that order

## pwntools
____________________
* To enter the interactive terminal type `ipython3`
* First line of code should always be `from pwn import *`
* Put the architecture next using `context.arch = 'amd64'` (Assuming the file is 64-bit)
* When cracking into an executable: `p = process("filename")`
* When cracking into a remote server: `p = remote("ip", port_number)`
* Use `p.recv()` to show anything that the executable is printing
* Use `p.sendline()` or `p.send()` to send the payload
* Use `elf = ELF("filename")` to get any important information about the executable
    - Use `elf.got` to get the values inside of the GOT
    - Use `elf.sym` to get the functions inside of the file
    
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
#### When to Use:
* If `gets` is used to get data in the executable

#### Application:
* This is used to overrwrite existing local variables
* Find the local variable that you want to overwrite using r2 (it will look like `var int64_t var_20h @ rbp-0x20`)
* Add 4 bytes in 32-bit and 8 bytes in 64-bit for return address

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
    * ```python
    from pwn import *
    offset = 44 # it's usually 44, but it might not be
    function_address = ___
    pop_address = ___
    argument = ___
    inject = b"a" * p32(offset) + p32(function_address) + p32(pop_address) + p32(argument)
    ```
* 64-bit:
    * ```python
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
1. Start with `%1$p`, `%2$p`, and continue until you see the hex value for what you input (if you input `%p` the hex will be `0x20702520`)
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
