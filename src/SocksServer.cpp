#include <cstring>
#include <signal.h>

#include <arpa/inet.h>

#include <iostream>
#include <string>

#include "SocksServer.hpp"
#include "SocksDef.hpp"


#define MAXPENDING 200

#ifndef USERNAME
    #define USERNAME "username"
#endif
#ifndef PASSWORD
    #define PASSWORD "password"
#endif


using namespace std;


// handle sig_pipe that can crash the app otherwise
void sig_handler(int signum) 
{
    
}


int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz) 
{
    if(recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] > max_sz)
        return false;

    uint8_t sz = buffer[0];
    if(recv_sock(sock, (char*)buffer, sz) != sz)
        return -1;

    return sz;
}


bool check_auth(int sock)
{
    uint8_t buffer[128];
    if(recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] != 1)
        return false;
    int sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
        return false;
    buffer[sz] = 0;
    if(strcmp((char*)buffer, USERNAME))
        return false;
    sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
        return false;
    buffer[sz] = 0;
    if(strcmp((char*)buffer, PASSWORD))
        return false;
    buffer[0] = 1;
    buffer[1] = 0;
    return send_sock(sock, (const char*)buffer, 2) == 2;
}


//
// SocksTunnelServer
// 
SocksTunnelServer::SocksTunnelServer(int serverfd, int serverPort)
: m_serverfd(serverfd)
, m_serverPort(serverPort)
{
    m_internalBuffer.resize(BUF_SIZE);
}


SocksTunnelServer::~SocksTunnelServer()
{
    shutdown(m_serverfd, SHUT_RDWR);
    close(m_serverfd);
}


int SocksTunnelServer::init()
{
    std::cout << "handle_connection" << std::endl;

    // Here we need to split ! 
    // we are in the TeamServer

    MethodIdentificationPacket packet;
    int read_size = recv_sock(m_serverfd, (char*)&packet, sizeof(MethodIdentificationPacket));

    std::cout << "MethodIdentificationPacket " << std::to_string(read_size) << std::endl;

    if(read_size != sizeof(MethodIdentificationPacket) || packet.version != 5)
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    read_size = recv_sock(m_serverfd, &m_internalBuffer[0], packet.nmethods);

    std::cout << "packet.nmethods " << std::to_string(read_size) << std::endl;

    if(read_size != packet.nmethods)
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    MethodSelectionPacket methode_response(METHOD_NOTAVAILABLE);
    for(unsigned i(0); i < packet.nmethods; ++i) 
    {
        #ifdef ALLOW_NO_AUTH
            if(m_internalBuffer[i] == METHOD_NOAUTH)
                methode_response.method = METHOD_NOAUTH;
        #endif
        if(m_internalBuffer[i] == METHOD_AUTH)
            methode_response.method = METHOD_AUTH;
    }

    int write_size = send_sock(m_serverfd, (const char*)&methode_response, sizeof(MethodSelectionPacket)) ;

    std::cout << "MethodSelectionPacket " << std::to_string(write_size) << std::endl;

    if(write_size != sizeof(MethodSelectionPacket) || methode_response.method == METHOD_NOTAVAILABLE)
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    if(methode_response.method == METHOD_AUTH)
        if(!check_auth(m_serverfd))
        {
            shutdown(m_serverfd, SHUT_RDWR);
            close(m_serverfd);
            return 0;
        }


    std::cout << "[+] HandShak ok !!! " << std::endl;   

    SOCKS5RequestHeader header;
    read_size = recv_sock(m_serverfd, (char*)&header, sizeof(SOCKS5RequestHeader));

    if(read_size != sizeof(SOCKS5RequestHeader) || header.version != 5 || header.cmd != CMD_CONNECT || header.rsv != 0)
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    std::cout << "SOCKS5RequestHeader " << std::to_string(read_size) << std::endl;

    if(header.atyp != ATYP_IPV4)
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    SOCK5IP4RequestBody req;
    read_size = recv_sock(m_serverfd, (char*)&req, sizeof(SOCK5IP4RequestBody));

    std::cout << "SOCK5IP4RequestBody " << std::to_string(read_size) << std::endl;

    if(read_size != sizeof(SOCK5IP4RequestBody))
    {
        shutdown(m_serverfd, SHUT_RDWR);
        close(m_serverfd);
        return 0;
    }

    m_ipDst = req.ip_dst;
    m_port = req.port;

    return 1;
}


int SocksTunnelServer::finishHandshack()
{
    SOCKS5Response response;
    response.ip_src = 0;
    response.port_src = m_serverPort;
    send_sock(m_serverfd, (const char*)&response, sizeof(SOCKS5Response));

    return 1;
}


int SocksTunnelServer::process(std::string& dataIn, std::string& dataOut)
{
    if(dataIn.size()>0)
        send_sock(m_serverfd, dataIn.data(), dataIn.size());

    ssize_t bytes_received;
    bool isDataAvailable;

    isDataAvailable = readAllDataFromSocket(m_serverfd, &m_internalBuffer[0], bytes_received);
    if(isDataAvailable && bytes_received <= 0)
        return -1;

    dataOut.assign(&m_internalBuffer[0], bytes_received);

    return 1;
}


// https://fr.manpages.org/fd_isset/2
// https://man7.org/linux/man-pages/man2/recv.2.html
//
// SocksServer
// 
SocksServer::SocksServer(int serverPort)
: m_serverPort(serverPort)
{

}

SocksServer::~SocksServer() 
{ 
    m_isStoped=true;
    this->m_socks5Server->join();
}


void SocksServer::launch()
{
    this->m_socks5Server = std::make_unique<std::thread>(&SocksServer::handleConnection, this);
}


void SocksServer::stop()
{
    m_isStoped=true;
}


int SocksServer::createServerSocket(struct sockaddr_in &echoclient) 
{
    int serversock;
    struct sockaddr_in echoserver;

    if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) 
    {
        std::cout << "[-] Could not create socket.\n";
        return -1;
    }

    // Construct the server sockaddr_in structure 
    memset(&echoserver, 0, sizeof(echoserver));       // Clear struct 
    echoserver.sin_family = AF_INET;                  // Internet/IP 
    echoserver.sin_addr.s_addr = htonl(INADDR_ANY);   // Incoming addr 
    echoserver.sin_port = htons(m_serverPort);       // server port 

    // Bind the server socket 
    if (bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) 
    {
        std::cout << "[-] Bind error.\n";
        return -1;
    }

    // Listen on the server socket 
    if (listen(serversock, MAXPENDING) < 0) 
    {
        std::cout << "[-] Listen error.\n";
        return -1;
    }
    return serversock;
}


int SocksServer::handleConnection()
{
    struct sockaddr_in echoclient;
    int listen_sock = createServerSocket(echoclient);
    
    if(listen_sock == -1) 
    {
        std::cout << "[-] Failed to create server\n";
        return -1;
    }

    signal(SIGPIPE, sig_handler);

    while(!m_isStoped) 
    {
        uint32_t clientlen = sizeof(echoclient);
        int clientsock;
        if ((clientsock = accept(listen_sock, (struct sockaddr *) &echoclient, &clientlen)) > 0) 
        {
            // 
            // mode indirect
            //
            std::unique_ptr<SocksTunnelServer> socksTunnelServer = std::make_unique<SocksTunnelServer>(clientsock, m_serverPort);
            int initResult = socksTunnelServer->init();
            if(initResult)
                m_socksTunnelServers.push_back(std::move(socksTunnelServer));
            else
                printf("SocksTunnelServer init failed");
        }
    }

    return 1;
}

