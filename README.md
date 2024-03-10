# Winnti for Linux

https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a

The Linux version of Winnti is comprised of two files: a main backdoor (libxselinux) and a library (libxselinux.so) used to hide it’s activity on an infected system.

https://digital.nhs.uk/cyber-alerts/2019/cc-3070

Winnti Linux is an updated variant of the Winnti backdoor, created by the advanced persistent threat group of the same name.

Winnti Linux's primary module, called libxselinux, is a lightly modified version of the open-source Azazel rootlet. Once installed, it will decrypt an embedded port configuration file before connecting to a command and control server using a variety of protocols (HTTP, ICMP, and custom TCP/UDP) and modifying commonly used functions to disguise its operations.

# Arrival Details

https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/Backdoor.Linux.WINNTI.F

This Backdoor drops the following files:

- if 0 is passed as an argument:

  - /var/run/libudev.pid

- if 1 is passed as an argument:
  - /var/run/libudev.pid
  - /var/run/libudev1.pid

It adds the following processes:

    HIDE_THIS_SHELL=x /lib/libxselinux 0 &
    /lib/libxselinux 0
    /usr/sbin/dmidecode | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null

# Information Theft

This Backdoor gathers the following data:

- UUID

# Other Details

This Backdoor requires the existence of the following files to properly run:

- /lib/libxselinux.so

It does the following:

- It requires being executed in the following directory:
  - /lib

It accepts the following parameters:

- 0
- 1

# Modified Functions

- open, open64
- fopen, fopen64
- readdir, readdir64

- opendir, rmdir

- link, unlink, unlinkat

- stat, stat64. xlstat, lstat64, \_\_lxstat64, \_\_xstat, \_\_xstat64, x\_\_lxstat
