ipredir
=======

IP redirection+NAT for Windows

Rewrites outgoing packets to redirect which IP they are headed to as well as performing standard NAT functions for any redirected packets.

Compilation
===========

ipredir requires the [MSVC binary package of WinDivert](http://reqrypt.org/windivert.html) to compile and function.

The ipredir project looks for WinDivert headers and library files within the original directory structure of the zip file, once it has been extracted within the ipredir source directory (i.e. `ipredir\WinDivert-1.1.6-MSVC\include\windivert.h`)

Execution
=========

ipredir requires a WinDivert DLL and kernel driver to run. These files must be placed in the same location as ipredir.exe

Since ipredir is a 32-bit program, it will utilize the 32-bit DLL found at `WinDivert-1.1.6-MSVC\x86\WinDivert.dll`

The kernel driver you use depends on the architecture of the system you are running ipredir on. The files are located at `WinDivert-1.1.6-MSVC\x86\WinDivert32.sys` and `WinDivert-1.1.6-MSVC\amd64\WinDivert64.sys`. If you are unsure which one you need, simply copy both to the location of ipredir.exe.

Usage:
------
`ipredir [-d] <rule> [rule...]`

The optional -d flag sets "debug mode" which will output data about every incoming/outgoing packet.

A redirection "rule" is of the format:

`oldip[,oldip[,oldip[...]]]=newip`

where any packets headed for 'oldip' will be redirected to 'newip'

Examples:
  + `ipredir 1.2.3.4=192.168.1.1`
    -  Any packet sent to 1.2.3.4 will be redirected to 192.168.1.1
  + `ipredir 1.2.3.4,1.2.3.5=192.168.1.1`
    -  Any packet sent to either 1.2.3.4 or 1.2.3.5 will be redirected to 192.168.1.1
  + `ipredit 1.2.3.4,1.2.3.5=192.168.1.1 2.3.4.5=192.168.2.1`
    -  Any packet sent to either 1.2.3.4 or 1.2.3.5 will be redirected to 192.168.1.1
    -  Any packet sent to 2.3.4.5 will be redirected to 192.168.2.1
