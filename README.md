Welcome to the GitHub of the SberMarket development team (service formerly known as [Instamart](https://github.com/nstmrt)). We are currently working on creating the leading service on the Russian e-shopping market. The service includes 3 applications, a website, 200 micro-services, as well as a PaaS, and is intended to cope with high traffic loads.


# Traffic dump from several Linux hosts

The given tool is designed to simultaneously dump traffic from multiple Linux hosts in real time via SSH and receive the incoming flow through a single Wireshark window. Conversion into the pcapng format is done using dumpcap (part of the Wireshark package, with no additional installation required).

## Installation
---
Golang is needed to compile or run the application through:
```
go run multipleDump.go
```
The application can also be compiled. For ease of compilation, you can use the build_win_linux_macos.sh script. Next, use the binary file and the hosts.conf config. **Wireshark version 3.6 or higher is required to run.**

## Examples of configuration
---

The hosts.conf file contains the config in json format. It also contains paths for Wireshark binaries in different operating systems like Windows and MacOS. No path is needed for Linux.

The following is a selection of elements, each representing settings for access via SSH to one Linux host, as well as parameters for running tcpdump on a remote host. Example of an element:

```
      {
         "UserHost":"user@10.10.10.10",
         "HostPort":"-p 21059",
         "Key":"-i $HOME/.ssh/id_rsa.priv",
         "Interface":"any",
         "PcapFilter":"not tcp port ssh and host 10.1.1.1",
         "Timeout":"100"
      }
```
All the settings are in the format required by the standard SSH client and tcpdump. The UserHost, HostPort, and Key fields are the keys that must be granted to the standard SSH client on the master device in order to log into a remote host. In case any of the parameters is redundant, replace it with a space value.
The PcapFilter and Interface are the parameters needed for running tcpdump on a remote host.

**Different values can be entered in the SSH parameters, as they are intended for the SSH command.** Any parameter can be entered into the config in the same format if the SSH accepts it.
For example:
```
      {   "UserHost":"-J user.my@10.2.2.2 user.my@10.10.10.10",
          "HostPort":"-p 22",
          "Key":"-i C:\\work\\keys\\key_pass\\ssh_key.priv",
          "Interface":"eth2",
          "PcapFilter":"host 8.8.8.8",
          "Timeout":"100"
      }
```


If your connection parameters to the host are specified in the SSH client config (in ~/.ssh/config for unix-like os) as follows:

```
Host JumpHost
  IdentityFile /Users/user/.ssh/id_rsa.priv
  Hostname 10.2.2.2
  User user.my

Host host1
  IdentityFile /Users/user/.ssh/id_rsa.priv
  ProxyJump JumpHost
  Hostname 10.10.10.10
  User user.my
```

and you need to receive a dump from host1, then simply input the name of the host from the SSH config in the config UserHost parameter. For example:

```
      {
          "UserHost":"host1",
          "HostPort":" ",
          "Key":" ",
          "Interface":"eth2",
          "PcapFilter":"host 8.8.8.8",
          "Timeout":"100"
      }
```
Insert space values into the HostPort and Key parameters.

## Parameters
---

**UserHost** - user@host (SSH parameter).

**HostPort** - SSH parameter for specifying the port (mandatory with -p. SSH parameter).

**Key** - path to the private key that the Linux host uses to grant access (mandatory with -i. SSH parameter).

**Interface** - the name of the interface that is transferring the dump (this is a parameter of the tcpdump command on the remote host).

**PcapFilter** - - the filter that is passed to the tcpdump command.

**Timeout** - tcpdump is launched with the timeout command for security on the remote host to make sure that it does not experience timeout and does not stall on certain processes in case of errors/connection failures. The parameter can be set to 0, however this action entails certain risks.

## Running a binary file
---
MAC(after compilation):
```
 ./multipleDump.bin.Macos
```
Windows:
```
.\multipleDump.exe
```
Linux:
```
./multipleDump.bin.Linux
```

Wireshark will run automatically, since the paths to its binary files are stated in the header of the config. The path to a binary that does not correspond to your operating system can be replaced with a space value.