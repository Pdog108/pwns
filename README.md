# PWN Assignments

These 16 problems are re-mixes of a beautiful set of introductory vulnerabilities from the 2020 Sunshine CTF.  I have the original binaries at: https://github.com/AndyNovo/speedruns
 
You can find write-ups of those problems when you get stuck, but these will have their own attributes that are adjusted for you.

We will release the problems in batches over the 7-weeks of this course.

Good luck, ask lots of questions.

Notes for this Project:

    Before starting each speedrun make sure to check the security features on the binary exec file:
    command to run: checksec --file=<filename>
        RELRO (Relocation Read-Only):
            1. Full: All GOT entries are read-only after initialization.
            2. Partial: Some GOT entries are writable after initialization.
            3. None: All GOT entries are writable.
            Importance: Full RELRO prevents overwriting GOT entries, making it harder to exploit certain types of vulnerabilities like buffer overflows.

        Stack Canary:
            1. Enabled: Stack canaries are present.
            2. Disabled: Stack canaries are not present.
            Importance: Stack canaries protect against stack buffer overflow attacks by checking for changes to the canary value, terminating the program if the canary is altered.

        NX (No Execute):
            1. NX enabled: Memory is non-executable.
            2. NX disabled: Memory is executable.
            Importance: NX prevents the execution of code on the stack or heap, making it more difficult to execute shellcode placed in those areas.

        PIE (Position Independent Executable):
            1. PIE enabled: Code is position-independent.
            2. PIE disabled: Code is not position-independent.
            Importance: PIE randomizes the base address of the executable, making it harder to predict the location of gadgets or functions, which complicates ROP (Return-Oriented Programming) exploitation.

        RPATH (Run-time library search path):
            1. Present: An RPATH is present.
            2. Not present: No RPATH is present.
            Importance: An RPATH can be used to specify additional directories to search for shared libraries, potentially leading to vulnerabilities if not used securely.

        No PIE --> ROP
        NX Disabled --> shellcode
        PARTIAL/NO RELRO --> libc exploit


    General Guideline for doing the speedruns:
        1. r2 executable
        2. run code exploit.py (to create the python script that we are going to use to solve the speedrun) (this will automatically open up a new file exploit.py in VSCode)
        3. Then write the exploit. (make sure pwn tools is installed, you can do this by running: pip install pwn tools)
        4. Then you can run ipython3 -i exploit.py
        5. Then the exploit is done and you can move onto the next one.

    Some ways to find the win function:
        1. Scroll up in the binary to find it.
        2. You can also run this command: rabin2 -s <filename> (The second one is the address of the win function if there is no PIE).
        3. You can use ipython3 to find the win function
            from pwn import *
            elf = ELF("./<filename>")
            elf.sym['win']
            hex(_)