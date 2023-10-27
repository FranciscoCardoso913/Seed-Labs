# CTF Buffer Overflow

## Challenge 2

### Information gathering

After reading the CTF statement in moodle we understood that the challenge would have to work harder to get the flag. Also, we had to add an exploit-example.py file to furtherly adapted. 
The next step was to list the files in the current directory with `ls -la`:

![ls](/img/ls-la-ctf52.png)

The files above showed up and we inspected each one of them:

- `exploit-example.py`: this file is an example of an exploit, taht alows us to run the `program` that it related to `main.c` or connect directly to `ctf-fsi.fe.up.pt:4000`, which is the server that we have to connect to in order to get the flag. Then, it takes a string that will be the input of the program. This file was given to us by the professor, and we had to adapt it to our needs;

- `flag.txt`: this file holds the flag that we want to get; It was just an experimental flag to run the exploit with `DEBUG=FALSE`.

- `main.c`: In this file we can check few changes: We have the buffer with 32 bytes and the meme_file, were we want to write the flag. But now, we have a new vector that has to be filled with a specific vallue in order to open the meme_file. This value is '0xfefc2324`. 

- `mem.txt`: this file holds a text that will be printed running the program with a small input.

- `program`: This is the file that we have to run in order to get the flag. It is a program that reads a string from the user and then prints it. However, it has a buffer overflow vulnerability, since it does not check the size of the input string. This means that we can write more bytes than the buffer can hold, and overwrite the meme_file in order to get the flag.

### Attack

After collecting and analyzing information, we identified an opportunity to exploit the administrator's use of a program with root permissions. Our method involved using a buffer overflow to carry out the attack. Here's how it was done:

1. 