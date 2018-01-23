# `linuxprivchecker.py` --- A Linux Privilege Escalation Checker for Python 2.7 and 3.x

## Summary
This script is intended to be executed locally on a Linux machine, with a Python version of 2.7 or 3.x, to enumerate basic system info and search for common privilege escalation vectors.

## Warning and Disclaimer
This script comes as-is with no promise of functionality or accuracy. Only use this script after you understand what every line in the script does. Only run this script on machines you have permission to access, and where you have permission to access any account, files and folders for that particular machine. Check that you are compliant with the laws and regulations that apply in your place of residence, before attempting to run this script.

This script is noisy by design and can therefore raise alarm bells. If you don't want this, don't run it.

## Usage
This script will try to check for if avenues along the following avenues:
* Basic system information as kernel version, linux distribution and hostname.
* Network information as IP addresses, routes, open connections and ARP caches.
* Current mounts and entries in /etc/fstab
* List of cron jobs and the ability to edit them.
* Scheduled tasks from systemd and possible access to journalctl.
* User, group and sudo information
* World-writeable directories and SUID binaries
* Password information in log files
* Accessibility to linux mail
* Information from the package manager and current processes
* Docker/lxc information

`linuxprivchecker.py` can be run with the following arguments
* `-h`, `--help`, should be self-explanatory.
* `-c`, `--color` for using colors in a terminal environment for easier navigation through the output.
* `-o filename`, `--outputfile filename` for storing the results in a local file.
* `-s IP:port`, `--send IP:port` to exfiltrate the information to a different machine, preferably running `linuxprivserver.py`
* `-q`, `--quiet` to not have the screen fill up with data. Useful in combination with `-o` and/or `-s`

The `linuxprivchecker.py` will produce from anywhere between a few 100 lines of output and up to 100,000 lines or even more, depending on the situation. Interpretation of the output is left as an exercise for the reader.

### The `linuxprivserver.py`, data exfiltration made easy
`linuxprivchecker.py` can be used in combination with `linuxprivserver.py` to directly exfiltration any gathered information to another machine. For this, run `linuxprivserver.py` on the receiving end and additionally you can provide the following options:
* `--ip IP` to set up a specific listening IP address, defaults to all possible IP addresses
* `--port PortNumber` to set up a port to listen on, defaults to 8080.
* `--outfile Filename` to save the received output to a file.
* `--quiet` to not output anything on the screen, useful in combination with `--outfile`.
Next run `linuxprivchecker.py` and make sure that `-s` is provided as argument with the correct IP and port information.

### About colorized output
The option `--color` in the `linuxprivchecker.py` script will propagate the terminal color commands to the output file and to the server (and any output file specified here). This means that when you open the file in an editor you might see some weird characters. This is left intentionally in place such that it is easier to browse through with commands as `less` and `cat`. If you want to remove the color formatting, run
`cat colorized_output.txt > plain_output.txt`
or simply do not provide the `--color` option to `linuxprivchecker.py`.

## Known issues
The `linuxprivchecker.py` cannot encode UTF-16 characters (yes, there is a rare case when a shell command issued by `linuxprivchecker.py` can contain output in `UTF-16` format). Some lines might therefore be missing in the output.

## Contribution
Compared to the original version, this script is refactored in a form that should make it easier to add additional commands.
Feel free to raise an issue or even better (as I do not pretend to know every nook and cranny of Linux) make a pull request.

In the original version there was also a small list of checking for vulnerable versions of Linux kernels and programs. This is removed in this version, as such a checklist can produce many false positives due to back-ported updates and quickly becomes outdated. I might consider to re-include a checklist against the latest non-vulnerable versions of programs, but it is currently not on the roadmap.

## Modification, Distribution, and Attribution
The original `linuxprivchecker.py` file was produced by Mike Czumak (T_v3rn1x) -- @SecuritySift at <https://github.com/sleventyeleven/linuxprivchecker/> with the notice in the following paragraph. This message still holds for `linuxprivchecker.py` in its current form and also holds for `linuxprivserver.py`.

You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's worth anything anyway :)
