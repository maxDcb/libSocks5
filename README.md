# libSocks5 Server

The library implement a simple socks5 server with the particularity that the actual Sock5 Server and the targeted host where SockerTunnelClient run can be splited. Thus the Socks traffic can be encapsulated within another protocol like TCP/HTTP/SMB...

proxychains ... <- tcp -> SocksServer <- http/tcp/smb -> SocksTunnelClient <- tcp -> target ip/port


## Build

```
mkdir build
cd build
cmake ..
make -j4
```

Run SocksServer localy:

```
./TestsSocksServer

proxychains nmap -sT -sC -sV 127.0.0.1 -p 1080
proxychains curl http://127.0.0.1:8080/test
```