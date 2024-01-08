# Quick start
mTLS v1.2 reverse client/server mutli-connection bidirectinal tunnel for Linux systems.

Prepare mTLS tunnel server:
```shell
$ mkdir ../build && cd ../build
$ cmake ../shadow && make
$ bash ../shadow/scripts/generate-certs.sh
$ sudo modprobe tls
$ # assume a server runs in the big IT cloud (port 2222)
$ ./shadow-server -6 --lport=2222 --ldir=. --ca=ca.crt --crt=server.crt --key=server.key
```

Run OpenSSH over mTLS:
```shell
$ sudo apt install openssh-server
# establish tunnel with sshd ::1:22 and remote server ::1:2222
$ ./shadow-client --rport=2222 --rhost=::1 --ca=ca.crt --crt=client.crt --key=client.key --robot=011 --lhost=::1 --lport=22
$ ssh -o "ProxyCommand socat - UNIX-CONNECT:./011.sock" robot011
....
```

Performance:
```shell
$ # assume a client runs on the external device (robot) with serial number 011
$ ./shadow-client --rport=2222 --rhost=::1 --ca=ca.crt --crt=client.crt --key=client.key --robot=011 --lhost=::1 --lport=5555
$ # assume external device listening port is 5555, emulate some
$ nc -6 -l 5555 > /dev/null
$ # connect to the unix socket on the server side and send some data
$ cat /dev/zero | pv | socat - UNIX-CONNECT:./011.sock
41,2GiB 0:00:40 [1,03GiB/s] [     <=>         ]
$ # maximum possible performance
$ cat /dev/zero | pv > /dev/null
44,5GiB 0:00:08 [6,44GiB/s] [           <=>   ]
```

About 1/6 of the maximum bandwidth for the current test.

Used software/hardware:
* i8700k 3.7GHz / 4.3GHz (Turbo boost)
* Vanilla Linux kernel 6.6.9, Spectre/Meltdown/etc... mitigations are compiled out
* GNU GCC 13.2
* Ubuntu 22.04.3 LTS


# Why another TLS tunnel?
mTLS tunnel implementation operates more or less like 'ssh -R' from OpenSSH server package. Specially designed for external devices/automatic systems/robots living outside company security perimeter (somewhere in the open Internet) using mTLS 1.2. The protocol is powered by customly issued CA and keys/certificates.

Since OpenSSH protocol is under constant heavy hacker attacks, using a bare OpenSSH reverse tunnel might be dangerous. On the other hand, if mTLS tunnel wraps OpenSSH protocol, remote ssh access becomes much more secure having two-factor protection.

NB! External devices and systems are called 'robots' in the source code and command line interface.

Target usecase:
1. There're a lot of external devices running a listening port locally
2. Due to security reasons, the devices block all incoming connections using local firewall, so there's no direct access to the particular device's listening port from the Internet
3. A device establish its own outgoing mTLS tunnel with a company's publicly available server
4. A device propagates a local listening port to a company's server's unix socket, it's very convenient, because a unix socket has a name and doesn't occupy network port
5. Company's internal infrastructure communicates with the unix sockets and eventually accesses a listening device port via a mTLS tunnel


Yeah, the design looks heavy, however, it has its own advantages:
1. don't care about exact IP address of the external device
2. don't care about an Internet Provider which an external device uses, even several NATs is not a problem anymore
3. provides high security level using mTLS 1.2 and customly issured CA,  keys and certificates
4. the design is still less heavy than VPN based solutions


# What's inside?

1. Linux ktls kernel module is used to provide better performance and simpler code. OpenSSL is used only at a connection establishment. Attention, OpenSSL 3.0.0+ is needed for ktls initialization.
2. Clients send keep alive messages. If something terrible happens, the server cleans its internal client list. The client exists in case of errors, so use with systemd service restarter to provide good reliability.
3. mTLS tunnel server could be either IPv6 or IPv4.
4. mTLS tunnel client might connect to both: IPv6 or IPv4 mTLS tunnel server and IPv6 or IPv4 device listening port. Hybrid v4/v6 connection is supported.


# Shortcomings

## Version 1.0

Each connection for each robot is served by a separate thread. It's going to be a problem at scale.
