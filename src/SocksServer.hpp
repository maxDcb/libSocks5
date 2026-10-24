#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <utility>

#include "SocksDef.hpp"

enum class SocksState 
{
    INIT,
    HANDSHAKE,
    RUN,
    STOP
};


class SocksTunnelServer
{
    public:
        SocksTunnelServer(socket_t serverfd, int serverPort, int id=0);
        ~SocksTunnelServer();

        int init();
        int finishHandshake();
        int failHandshake(Response response);
        int process(std::string& dataIn, std::string& dataOut);

        uint32_t getIpDst()
        {
            return m_ipDst;
        }
        AddressType getAddressType()
        {
            return m_addressType;
        }
        const std::string& getDestinationHost()
        {
            return m_destinationHost;
        }
        uint16_t getPort()
        {
            return m_port;
        }
        SocksState getState()
        {
            return m_state;
        }
        void setState(SocksState state)
        {
            m_state = state;
        }
        int getId()
        {
            return m_id;
        }

    private:
        SocketHandle m_serverfd;
        SocketWriteBuffer m_pendingWrite;
        bool m_dataSocketNonBlocking;
        int m_serverPort;

        AddressType m_addressType;
        uint32_t m_ipDst;
        std::string m_destinationHost;
        uint16_t m_port;

        SocksState m_state;
        int m_id;

        std::string m_internalBuffer;
};


class SocksServer
{

public:
    SocksServer(int serverPort=1080);
    ~SocksServer();

    void launch();
    void stop();
    void cleanTunnel();
    bool isServerStoped()
    {
        return m_isStoped;
    }
    bool isServerLaunched()
    {
        return m_isLaunched;
    }

    std::size_t tunnelCount();
    SocksTunnelServer* getTunnel(std::size_t idx);
    void resetTunnel(std::size_t idx);

private:
    socket_t createServerSocket(struct sockaddr_in &echoclient);
    int handleConnection();

    int m_serverPort;
    SocketHandle m_listen_sock;

    std::atomic_bool m_isLaunched;
    std::atomic_bool m_isStoped;
    bool m_socketRuntimeReady;
    std::unique_ptr<std::thread> m_socks5Server;

    std::mutex m_mutex;
    std::vector<std::unique_ptr<SocksTunnelServer>> m_socksTunnelServers;
    std::mutex m_handshakeMutex;
    std::vector<std::pair<int, socket_t>> m_handshakeSockets;
};
