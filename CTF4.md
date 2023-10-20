# CTF Linux Environment

## Information gathering

After reading the CTF statement in moodle we know that there is a script that is running periodically that will be the key to get the flag in this challenge. The first thing was to list the files in the current directory with `ls -la`:

![ls](ls-la.png)

The files above showed up and we inspected each one of them:

- `admin_note.txt`: this note gives us the hint that using the /tmp folder for the attack will be useful, since we have writing, reading and executing permissions in that folder;
- `env`: just an empty file called `env`, which refers to environment variables. It is useful to note that this file has a link to and `env` file located in the folder `tmp`;
- `main.c`: this file holds some C code that uses the [access](https://man7.org/linux/man-pages/man2/access.2.html) function which checks for user's permissions for a file. In this file we can see where the flag is stored: `/flags/flag.txt`;
- `my_script.sh`: this simple script exports the command `cat`, that can be used to write to a file, and the envinronment variables that exist in the `env` file. It also runs a file called `reader`;
- `reader`: if we inspect the contents of this file we will find a lot of gibberish. However, if we look closely we can see that the messages "Implement this in the near future! I'm going to check if the flag exists!" are written. These messages are the same ones from the `main.c` file. We can therefore conclude that `reader` is the executable of `main.c`.

In addition to all of this we also ran the command `cat /etc/cron.d/my_cron_script`:

![cronjob](cronjob.png)

This confirms that the file `my_script.sh` is being run every minute

## Ataque

After collecting and analyzing information, we identified an opportunity to exploit the administrator's use of a script with root permissions. Our method involved using LD_PRELOAD, an environmental variable, to carry out the attack. Here's how it was done:

1. **Selecting the Directory:** To initiate the attack, we decided to work within the 'tmp' directory. This directory would serve as the location where we could create the necessary files.

2. **Creating a Custom 'access' Function:** The script being executed by the administrator was using a function called 'access'. We created our version of this function to intercept its behavior. Our custom 'access' function was designed to copy the contents of the 'flag.txt' file and place them into a file we generated within the 'tmp' directory:

```C
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int access(const char *pathname, int mode){ 
system("cat /flags/flag.txt >> /tmp/our_flag.txt");
return 0;
}
```

3. **Compiling the Custom Function:** After creating our custom 'access' function, we compiled it into a dynamic linked library with the following commands: `gcc -fPIC -g -c mylib.c` and `gcc -shared -o libmylib.so.1.0.1 mylib.o -lc`.

4. **Modifying the 'LD_PRELOAD' Environment Variable:** To direct the script to use our custom 'access' function, we added an entry to the 'LD_PRELOAD' environment variable. This entry specified the path to the library containing our custom function, in this example: `export LD_PRELOAD=./libmylib.so.1.0.1`. This works because the script will load the code from our library first, making the program `reader` run our version of the `access` function.

5. **Creating the file to copy the flag:** We created a file named our_flag.txt in the /tmp folder. This file will be the one that will hold the flag when the script runs;

6. **Executing the Attack:** With our setup in place, we simply had to wait for the administrator to run the script. Once executed, the script used our custom 'access' function. As a result, the contents of 'flag.txt' were secretly copied to our designated file in the 'tmp' directory. This gave us access to the flag.


## What could the admin have done to prevent this attack

There are some things that we consider relevant to mention, that the admin could have done to prevent this attack:

- The message in the `admin_note.txt` file is also a hint that the admin could have used to prevent the attack. The admin could have removed the writing permissions in the /tmp folder, since it is a folder that is used to store temporary files, and the user should not have any type of permissions on that folder;
- The user had access to the `env` file, which is a file that holds environment variables. The admin could have removed the permissions to read **and write** that file, since it is not needed for the user to run the script. Having the possibility to export environment variables is a security vulnerability that the admin should have prevented;
- The admin could have also removed the permissions to read the `main.c` file, since it is not needed for the user to run the script;
