Tungsten Fabric Core Analyzer

Instructions to use Tungsten Fabric core Analyzer tool:  
Tungsten Fabric core Analyzer is a debug tool which, given a gcore
downloads the required debug binary and stripped binary files and runs a
GDB script to figure out what caused the failure Steps to use the script
- 1. python3 tf\_debugger <core file> - to run the script Command:
python3 tf\_debugger.py <core-file-name> Example: \# python3
tf\_debugger.py core.6144

1.  Python3 tf\_debugger <core file> [-f] <version> <id> - overrides the
    version and the id numbers read from the core file to download the
    binaries of the version and the id mentioned by the user after the
    flag [-f]. Command: python3 tf\_debugger.py <core-file-name> -f
    <build_version_num> <build_id_num>

Example: \# python3 tf\_debugger.py core.6144 -f 2002 3

1.  python3 tf\_debugger <core file> -gdb <gdb script.txt> - to pass a
    custom gdb script to run in place of the default one. Here
    custom.txt is the user provided gdb script Command: python3
    tf\_debugger.py <core-file-name> -gdb <gdb_commnands_file.txt>

Example: \# python3 tf\_debugger.py core.6144 -gdb custom.txt

1.  python3 tf\_debugger <core file> -f <version> <id> -gdb
    <gdb script.txt> - to override the version and the ID values read
    from the script and the pass a custom gdb script Command: python3
    tf\_debugger.py <core-file-name> -f <x> <y> -gdb
    <gdb_commnands_file.txt>

Example: \# python3 tf\_debugger.py core.6144 -f 2002 3 -gdb custom.txt

1.  python3 tf\_debugger -h (gives help instructions to the user)
    Command : python3 tf\_debugger.py <core-file-name> --help

Example: \#python3 tf\_debugger.py core.6144 --help

Things to change before using the tool: 1. The only change you will have
to make is a variable called ‘your\_location’ in the script which should
point to where the the script will be located on your machine Example:
\# debugger\_location = “/root/tf\_debugger”

Accessing the new file created 1. Once the script is run with the gcore,
it creates a directory named after the version and ID read from the
gcore. Directory example: 46\_1912

1.  Once it is clear which directory was created after the run, ‘cd’
    into the directory to find a debug binary with the name
    contrail-vrouter-agent.debug and a stripped binary with the name
    contrail-vrouter-agent-stripped Command: cd 46\_1912
2.  The binaries can be verified by running ‘file’ command on them.
    Command: file contrail-vrouter-agent.debug

3.  If the core file name is xyz, then a gdb output log file with the
    name xyz\_GDB.log file will be created in the same directory for
    easier mapping Command: vim core-file\_GDB.log

Things to know before using the tool: 1. The script will exit if the
operating system the gcore was generated on does not match the operating
system your machine is running on Exit message - The operating system
you are on is CentOS Linux and this is a gcore which was not generated
on the same operating system, please run the script on appropriate
operating system to get the right results 2. While passing the override
function, that is -f, the first parameter after the flag -f should be
the version number followed by a space and then the ID number 3. The
custom GDB script which the user might want to pass should be a ‘.txt’
file Seeing all the Information at one place: 1. Once the execution of
the program is complete, all the information is displayed under summary,
which will give you a better idea about the gcore file

Summary : AGENT: VROUTER AGENT VERSION OF THE GCORE : 1912 ID OF THE
GCORE : 46 THE HOST-NAME :
contrail-build-r1912-centos-46-generic-20200318134848.novalocal THE
BUILD\_TIME :2020-03-18 21:00:12.333442 The GDB output log file is
stored in the directory : 46\_1912 Change directory to view the GDB log
file The Default GDB script: 1. The default GDB script which runs when
the user does not mention any GDB script of their own is conveniently
named as default\_GDB\_commands.txt 2. Any changes that has to be made
to the default GDB script that the tool uses, this is the file that
needs to be changed
