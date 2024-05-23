#pragma once

#include <thread>
#include <vector>


class SocksTunnelServer
{
    public:
        SocksTunnelServer(int serverfd, int serverPort);
        ~SocksTunnelServer();

        int init();
        int finishHandshack();
        int process(std::string& dataIn, std::string& dataOut);

        uint32_t getIpDst()
        {
            return m_ipDst;
        }
        uint16_t getPort()
        {
            return m_port;
        }

    private:
        int m_serverfd;
        int m_serverPort;

        uint32_t m_ipDst;
        uint16_t m_port;

        std::string m_internalBuffer;
};


class SocksServer
{

public:
    SocksServer(int serverPort=1080);
    ~SocksServer(); 

    void launch();
    void stop();

    std::vector<std::unique_ptr<SocksTunnelServer>> m_socksTunnelServers;

private:
    int createListenSocket(struct sockaddr_in &echoclient) ;
    int createServerSocket(struct sockaddr_in &echoclient);
    int handleConnection();

    int m_serverPort;

    bool m_isStoped;
    std::unique_ptr<std::thread> m_socks5Server;

    
};