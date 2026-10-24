#include <cstring>
#include <signal.h>

#ifdef __linux__
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#elif _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <string>
#include <algorithm>
#include <chrono>
#include <future>

#include "SocksServer.hpp"
#include "SocksDef.hpp"


#define MAXPENDING 200

#ifndef USERNAME
    #define USERNAME "username"
#endif
#ifndef PASSWORD
    #define PASSWORD "password"
#endif


#ifdef __linux__
#elif _WIN32
    #pragma pack(push, 1)
#endif

// Handshake
struct MethodIdentificationPacket 
{
    uint8_t version, nmethods;
    // uint8_t methods[nmethods];
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif


struct MethodSelectionPacket 
{
    uint8_t version, method;
    MethodSelectionPacket(uint8_t met) : version(5), method(met) {}
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif

// Requests
struct SOCKS5RequestHeader 
{
    uint8_t version, cmd, rsv /* = 0x00 */, atyp;
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif


struct SOCK5IP4RequestBody 
{
    uint32_t ip_dst;
    uint16_t port;
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif


struct SOCK5DNameRequestBody 
{
    uint8_t length;
    // uint8_t dname[length]; 
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif


// Responses
struct SOCKS5Response 
{
    uint8_t version, cmd, rsv /* = 0x00 */, atyp;
    uint32_t ip_src;
    uint16_t port_src;
    
    SOCKS5Response(Response response = Response::Succeeded)
        : version(5),
          cmd(static_cast<uint8_t>(response)),
          rsv(0),
          atyp(static_cast<uint8_t>(AddressType::IPv4)),
          ip_src(0),
          port_src(0)
    {
    }
} 
#ifdef __linux__
    __attribute__((packed));
#elif _WIN32
    ;
#endif


#ifdef __linux__
#elif _WIN32
    #pragma pack(pop)
#endif


using namespace std;

namespace
{
constexpr int SOCKS_HANDSHAKE_TIMEOUT_MS = 5000;
constexpr std::size_t SOCKS_MAX_PENDING_HANDSHAKES = 32;
constexpr std::size_t SOCKS_MAX_ACTIVE_TUNNELS = 128;

int recv_sock_timeout(socket_t sock, char* buffer, uint32_t size, int timeoutMs)
{
    int index = 0;
    while(size)
    {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(sock, &readFds);

        timeval timeout{};
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;

#ifdef _WIN32
        const int ready = select(0, &readFds, nullptr, nullptr, &timeout);
#else
        const int ready = select(sock + 1, &readFds, nullptr, nullptr, &timeout);
#endif
        if(ready <= 0)
            return -1;

        const int ret = recv(sock, &buffer[index], size, 0);
        if(ret <= 0)
            return (!ret) ? index : -1;

        index += ret;
        size -= ret;
    }
    return index;
}

bool send_socks_response(socket_t sock, Response code, uint16_t port = 0)
{
    SOCKS5Response response(code);
    response.port_src = htons(port);
    return send_sock(sock, reinterpret_cast<const char*>(&response), sizeof(SOCKS5Response)) == sizeof(SOCKS5Response);
}

bool send_auth_response(socket_t sock, uint8_t status)
{
    uint8_t buffer[2] = {1, status};
    return send_sock(sock, reinterpret_cast<const char*>(buffer), sizeof(buffer)) == sizeof(buffer);
}
} // namespace


int read_variable_string(socket_t sock, uint8_t *buffer, uint8_t max_sz)
{
    if(recv_sock_timeout(sock, (char*)buffer, 1, SOCKS_HANDSHAKE_TIMEOUT_MS) != 1 || buffer[0] > max_sz)
        return false;

    uint8_t sz = buffer[0];
    if(recv_sock_timeout(sock, (char*)buffer, sz, SOCKS_HANDSHAKE_TIMEOUT_MS) != sz)
        return -1;

    return sz;
}


bool check_auth(socket_t sock)
{
    uint8_t buffer[128];
    if(recv_sock_timeout(sock, (char*)buffer, 1, SOCKS_HANDSHAKE_TIMEOUT_MS) != 1 || buffer[0] != 1)
        return false;
    int sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
        return false;
    buffer[sz] = 0;
    if(strcmp((char*)buffer, USERNAME))
    {
        send_auth_response(sock, 1);
        return false;
    }
    sz = read_variable_string(sock, buffer, 127);
    if(sz == -1)
    {
        send_auth_response(sock, 1);
        return false;
    }
    buffer[sz] = 0;
    if(strcmp((char*)buffer, PASSWORD))
    {
        send_auth_response(sock, 1);
        return false;
    }
    return send_auth_response(sock, 0);
}


//
// SocksTunnelServer
// 
SocksTunnelServer::SocksTunnelServer(socket_t serverfd, int serverPort, int id)
: m_serverfd(serverfd)
, m_dataSocketNonBlocking(false)
, m_serverPort(serverPort)
, m_addressType(AddressType::IPv4)
, m_ipDst(0)
, m_port(0)
, m_state(SocksState::INIT)
, m_id(id)
{
    m_internalBuffer.resize(BUF_SIZE);
}


SocksTunnelServer::~SocksTunnelServer() = default;


int SocksTunnelServer::init()
{
    MethodIdentificationPacket packet;
    int read_size = recv_sock_timeout(m_serverfd.get(), (char*)&packet, sizeof(MethodIdentificationPacket), SOCKS_HANDSHAKE_TIMEOUT_MS);

    if(read_size != sizeof(MethodIdentificationPacket) || packet.version != 5)
    {
        m_serverfd.reset();
        return 0;
    }

    if(packet.nmethods > m_internalBuffer.size())
    {
        m_serverfd.reset();
        return 0;
    }

    read_size = recv_sock_timeout(m_serverfd.get(), &m_internalBuffer[0], packet.nmethods, SOCKS_HANDSHAKE_TIMEOUT_MS);

    if(read_size != packet.nmethods)
    {
        m_serverfd.reset();
        return 0;
    }

    MethodSelectionPacket methode_response(static_cast<uint8_t>(Method::NotAvailable));
    for(unsigned i(0); i < packet.nmethods; ++i)
    {
        if(ALLOW_NO_AUTH && m_internalBuffer[i] == static_cast<uint8_t>(Method::NoAuth))
            methode_response.method = static_cast<uint8_t>(Method::NoAuth);
        if(m_internalBuffer[i] == static_cast<uint8_t>(Method::Auth))
            methode_response.method = static_cast<uint8_t>(Method::Auth);
    }

    int write_size = send_sock(m_serverfd.get(), (const char*)&methode_response, sizeof(MethodSelectionPacket)) ;

    if(write_size != sizeof(MethodSelectionPacket) || methode_response.method == static_cast<uint8_t>(Method::NotAvailable))
    {
        m_serverfd.reset();
        return 0;
    }

    if(methode_response.method == static_cast<uint8_t>(Method::Auth))
        if(!check_auth(m_serverfd.get()))
        {
            m_serverfd.reset();
            return 0;
        }


    SOCKS5RequestHeader header;
    read_size = recv_sock_timeout(m_serverfd.get(), (char*)&header, sizeof(SOCKS5RequestHeader), SOCKS_HANDSHAKE_TIMEOUT_MS);

    if(read_size != sizeof(SOCKS5RequestHeader) || header.version != 5 || header.rsv != 0)
    {
        send_socks_response(m_serverfd.get(), Response::GenError);
        m_serverfd.reset();
        return 0;
    }

    if(header.atyp == static_cast<uint8_t>(AddressType::IPv4))
    {
        SOCK5IP4RequestBody req;
        read_size = recv_sock_timeout(m_serverfd.get(), (char*)&req, sizeof(SOCK5IP4RequestBody), SOCKS_HANDSHAKE_TIMEOUT_MS);

        if(read_size != sizeof(SOCK5IP4RequestBody))
        {
            m_serverfd.reset();
            return 0;
        }

        m_addressType = AddressType::IPv4;
        m_ipDst = req.ip_dst;
        m_destinationHost.clear();
        m_port = req.port;
        if(header.cmd != static_cast<uint8_t>(Command::Connect))
        {
            send_socks_response(m_serverfd.get(), Response::CommandNotSupported);
            m_serverfd.reset();
            return 0;
        }
        return 1;
    }

    if(header.atyp == static_cast<uint8_t>(AddressType::DName))
    {
        SOCK5DNameRequestBody body;
        read_size = recv_sock_timeout(m_serverfd.get(), (char*)&body, sizeof(SOCK5DNameRequestBody), SOCKS_HANDSHAKE_TIMEOUT_MS);
        if(read_size != sizeof(SOCK5DNameRequestBody) || body.length == 0 || body.length > m_internalBuffer.size())
        {
            send_socks_response(m_serverfd.get(), Response::GenError);
            m_serverfd.reset();
            return 0;
        }

        read_size = recv_sock_timeout(m_serverfd.get(), &m_internalBuffer[0], body.length, SOCKS_HANDSHAKE_TIMEOUT_MS);
        if(read_size != body.length)
        {
            m_serverfd.reset();
            return 0;
        }

        uint16_t port = 0;
        read_size = recv_sock_timeout(m_serverfd.get(), reinterpret_cast<char*>(&port), sizeof(port), SOCKS_HANDSHAKE_TIMEOUT_MS);
        if(read_size != sizeof(port))
        {
            m_serverfd.reset();
            return 0;
        }

        m_addressType = AddressType::DName;
        m_ipDst = 0;
        m_destinationHost.assign(m_internalBuffer.data(), body.length);
        m_port = port;
        if(header.cmd != static_cast<uint8_t>(Command::Connect))
        {
            send_socks_response(m_serverfd.get(), Response::CommandNotSupported);
            m_serverfd.reset();
            return 0;
        }
        return 1;
    }

    if(header.atyp == static_cast<uint8_t>(AddressType::IPv6))
    {
        recv_sock_timeout(m_serverfd.get(), &m_internalBuffer[0], 16, SOCKS_HANDSHAKE_TIMEOUT_MS);
        uint8_t ignoredPort[2];
        recv_sock_timeout(m_serverfd.get(), reinterpret_cast<char*>(ignoredPort), sizeof(ignoredPort), SOCKS_HANDSHAKE_TIMEOUT_MS);
    }

    send_socks_response(m_serverfd.get(), Response::AddressTypeNotSupported);
    m_serverfd.reset();
    return 0;
}


int SocksTunnelServer::finishHandshake()
{
    return send_socks_response(m_serverfd.get(), Response::Succeeded,
                               static_cast<uint16_t>(m_serverPort)) ? 1 : 0;
}


int SocksTunnelServer::failHandshake(Response response)
{
    return send_socks_response(m_serverfd.get(), response) ? 1 : 0;
}


int SocksTunnelServer::process(std::string& dataIn, std::string& dataOut)
{
    if (!m_dataSocketNonBlocking)
    {
        if (!set_socket_non_blocking(m_serverfd.get(), true))
            return -1;
        m_dataSocketNonBlocking = true;
    }

    const BufferedSendStatus sendStatus = m_pendingWrite.appendAndFlush(m_serverfd.get(), dataIn);
    if (sendStatus == BufferedSendStatus::Error || sendStatus == BufferedSendStatus::Overflow)
        return -1;

    DrainStatus status = readAllAvailableNow_(m_serverfd.get(), dataOut, 0);
    if(status == DrainStatus::Error || status == DrainStatus::Disconnected)
        return -1;

    return 1;
}


// https://fr.manpages.org/fd_isset/2
// https://man7.org/linux/man-pages/man2/recv.2.html
//
// SocksServer
// 
SocksServer::SocksServer(int serverPort)
: m_serverPort(serverPort)
, m_isLaunched(false)
, m_isStoped(true)
, m_socketRuntimeReady(true)
{
    #ifdef __linux__
    #elif _WIN32
        WSADATA wsaData;
        m_socketRuntimeReady = WSAStartup(MAKEWORD(2,2), &wsaData) == 0;
    #endif
}


SocksServer::~SocksServer() 
{ 
    stop();
#ifdef _WIN32
    if (m_socketRuntimeReady)
        WSACleanup();
#endif
}


void SocksServer::launch()
{
    if (m_socks5Server || !m_socketRuntimeReady)
        return;
    m_isStoped.store(false);
    m_isLaunched.store(false);
    m_socks5Server = std::make_unique<std::thread>(&SocksServer::handleConnection, this);
}


void SocksServer::stop()
{
    m_isStoped.store(true);
    m_listen_sock.reset();
    {
        std::lock_guard<std::mutex> lock(m_handshakeMutex);
        for (const auto& handshake : m_handshakeSockets)
            ::shutdown(handshake.second, SHUT_RDWR);
    }

    if(m_socks5Server)
    {
        m_socks5Server->join();
        m_socks5Server.reset();
    }
    m_isLaunched.store(false);
}


socket_t SocksServer::createServerSocket(struct sockaddr_in &echoclient)
{
    socket_t serversock;
    struct sockaddr_in echoserver;

    if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET_VALUE)
    {
        return -1;
    }

    // Set the SO_REUSEADDR option
    int opt = 1;
    if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) 
    {
        #ifdef __linux__
            close(serversock);
        #elif _WIN32
            closesocket(serversock);
        #endif
        return -1;
    }

    // Construct the server sockaddr_in structure 
    memset(&echoserver, 0, sizeof(echoserver));       // Clear struct 
    echoserver.sin_family = AF_INET;                  // Internet/IP 
    echoserver.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Local clients only
    echoserver.sin_port = htons(m_serverPort);       // server port 

    // Bind the server socket 
    if (::bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0)
    {
        #ifdef __linux__
            close(serversock);
        #elif _WIN32
            closesocket(serversock);
        #endif
        return -1;
    }

    // Listen on the server socket 
    if (listen(serversock, MAXPENDING) < 0) 
    {
        #ifdef __linux__
            close(serversock);
        #elif _WIN32
            closesocket(serversock);
        #endif
        return -1;
    }
    return serversock;
}


int SocksServer::handleConnection()
{
    struct sockaddr_in echoclient;
    m_listen_sock.reset(createServerSocket(echoclient));

    if(m_listen_sock.get() == INVALID_SOCKET_VALUE)
    {
        m_isStoped.store(true);
        m_isLaunched.store(false);
        return -1;
    }

    if (m_isStoped.load())
    {
        m_listen_sock.reset();
        return 0;
    }

#ifdef __linux__
    signal(SIGPIPE, sig_handler);
#elif _WIN32
#endif

    m_isLaunched.store(true);
    int idSocksTunnelServer=0;
    struct HandshakeJob
    {
        std::future<std::unique_ptr<SocksTunnelServer>> result;
    };
    std::vector<HandshakeJob> handshakes;

    auto collectHandshakes = [&]
    {
        for (auto job = handshakes.begin(); job != handshakes.end();)
        {
            if (job->result.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
            {
                ++job;
                continue;
            }
            std::unique_ptr<SocksTunnelServer> tunnel = job->result.get();
            if (tunnel)
            {
                bool atCapacity = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_socksTunnelServers.erase(
                        std::remove_if(m_socksTunnelServers.begin(), m_socksTunnelServers.end(),
                            [](const std::unique_ptr<SocksTunnelServer>& item) { return item == nullptr; }),
                        m_socksTunnelServers.end());
                    atCapacity = m_socksTunnelServers.size() >= SOCKS_MAX_ACTIVE_TUNNELS;
                    if (!atCapacity)
                        m_socksTunnelServers.push_back(std::move(tunnel));
                }
                if (atCapacity)
                    tunnel->failHandshake(Response::ConnectionNotAllowed);
            }
            job = handshakes.erase(job);
        }
    };

    while(!m_isStoped)
    {
        collectHandshakes();
        if (handshakes.size() >= SOCKS_MAX_PENDING_HANDSHAKES)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        const socket_t listenSocket = m_listen_sock.get();
        if (listenSocket == INVALID_SOCKET_VALUE)
            break;
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(listenSocket, &readFds);
        timeval timeout{};
        timeout.tv_usec = 50000;
#ifdef _WIN32
        const int ready = select(0, &readFds, nullptr, nullptr, &timeout);
#else
        const int ready = select(listenSocket + 1, &readFds, nullptr, nullptr, &timeout);
#endif
        if (ready <= 0)
            continue;

        int clientlen = sizeof(echoclient);
        socket_t clientsock = INVALID_SOCKET_VALUE;
#ifdef __linux__
        if ((clientsock = accept(listenSocket, (struct sockaddr *) &echoclient, (uint*)&clientlen)) != INVALID_SOCKET_VALUE)
#elif _WIN32
        if ((clientsock = accept(listenSocket, (struct sockaddr *) &echoclient, &clientlen)) != INVALID_SOCKET_VALUE)
#endif
        {
            configure_socket_io_timeouts(clientsock);
            const int tunnelId = idSocksTunnelServer;
            {
                std::lock_guard<std::mutex> lock(m_handshakeMutex);
                m_handshakeSockets.emplace_back(tunnelId, clientsock);
            }
            handshakes.push_back(HandshakeJob{
                std::async(std::launch::async, [this, clientsock, serverPort = m_serverPort, tunnelId]() mutable
                {
                    auto tunnel = std::make_unique<SocksTunnelServer>(clientsock, serverPort, tunnelId);
                    const bool initialized = tunnel->init() != 0;
                    {
                        std::lock_guard<std::mutex> lock(m_handshakeMutex);
                        m_handshakeSockets.erase(
                            std::remove_if(m_handshakeSockets.begin(), m_handshakeSockets.end(),
                                [tunnelId](const auto& handshake) { return handshake.first == tunnelId; }),
                            m_handshakeSockets.end());
                    }
                    if (!initialized)
                        return std::unique_ptr<SocksTunnelServer>();
                    return tunnel;
                })});
            idSocksTunnelServer++;
        }
    }

    for (auto& job : handshakes)
    {
        std::unique_ptr<SocksTunnelServer> tunnel = job.result.get();
        (void)tunnel;
    }
    m_listen_sock.reset();
    m_isLaunched.store(false);
    m_isStoped.store(true);

    return 1;
}


void SocksServer::cleanTunnel()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_socksTunnelServers.erase(std::remove_if(m_socksTunnelServers.begin(), m_socksTunnelServers.end(),
                             [](const std::unique_ptr<SocksTunnelServer>& ptr) { return ptr == nullptr; }),
              m_socksTunnelServers.end());
}

std::size_t SocksServer::tunnelCount()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_socksTunnelServers.size();
}

SocksTunnelServer* SocksServer::getTunnel(std::size_t idx)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if(idx >= m_socksTunnelServers.size())
        return nullptr;
    return m_socksTunnelServers[idx].get();
}

void SocksServer::resetTunnel(std::size_t idx)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if(idx < m_socksTunnelServers.size())
        m_socksTunnelServers[idx].reset();
}
