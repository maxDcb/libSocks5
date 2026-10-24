#include <cstring>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>


#include <signal.h>

#ifdef __linux__
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#elif _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <string>
#include <sstream>

#include "SocksTunnelClient.hpp"
#include "SocksDef.hpp"


using namespace std;

namespace
{
constexpr std::size_t SOCKS_CONNECT_WORKERS = 2;
constexpr std::size_t SOCKS_CONNECT_QUEUE_LIMIT = 32;

class ConnectWorkerPool
{
public:
    ConnectWorkerPool()
    {
        for (std::size_t index = 0; index < SOCKS_CONNECT_WORKERS; ++index)
            std::thread([this] { worker(); }).detach();
    }

    std::future<socket_t> submit(std::packaged_task<socket_t()>&& task, bool& accepted)
    {
        std::future<socket_t> result = task.get_future();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_tasks.size() >= SOCKS_CONNECT_QUEUE_LIMIT)
            {
                accepted = false;
                return result;
            }
            m_tasks.push_back(std::move(task));
        }
        accepted = true;
        m_ready.notify_one();
        return result;
    }

private:
    void worker()
    {
        while (true)
        {
            std::packaged_task<socket_t()> task;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_ready.wait(lock, [this] { return !m_tasks.empty(); });
                task = std::move(m_tasks.front());
                m_tasks.pop_front();
            }
            task();
        }
    }

    std::mutex m_mutex;
    std::condition_variable m_ready;
    std::deque<std::packaged_task<socket_t()>> m_tasks;
};

ConnectWorkerPool& connectWorkerPool()
{
    static ConnectWorkerPool* pool = new ConnectWorkerPool();
    return *pool;
}
} // namespace


std::string int_to_str(uint32_t ip) 
{
    ostringstream oss;
    for (unsigned i=0; i<4; i++) 
    {
        oss << ((ip >> (i*8) ) & 0xFF);
        if(i != 3)
            oss << '.';
    }
    return oss.str();
}

void close_socket(socket_t sock)
{
#ifdef __linux__
    close(sock);
#elif _WIN32
    closesocket(sock);
#endif
}


bool set_non_blocking(socket_t sock, bool enabled)
{
#ifdef _WIN32
    u_long mode = enabled ? 1UL : 0UL;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    const int flags = fcntl(sock, F_GETFL, 0);
    return flags >= 0 && fcntl(sock, F_SETFL,
                              enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
#endif
}

bool connect_with_timeout(socket_t sock, const sockaddr* address, socklen_t length,
                          const std::atomic_bool& cancelled,
                          std::chrono::steady_clock::time_point deadline)
{
    if (!set_non_blocking(sock, true))
        return false;

    const int result = connect(sock, address, length);
    if (result == 0)
    {
        return set_non_blocking(sock, false) && configure_socket_io_timeouts(sock);
    }

#ifdef _WIN32
    const int connectError = WSAGetLastError();
    if (connectError != WSAEWOULDBLOCK && connectError != WSAEINPROGRESS)
        return false;
#else
    if (errno != EINPROGRESS)
        return false;
#endif

    while (!cancelled.load())
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return false;
        const auto slice = std::min(std::chrono::milliseconds(100),
                                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now));
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(slice.count() / 1000);
        timeout.tv_usec = static_cast<long>((slice.count() % 1000) * 1000);
        fd_set writeFds;
        FD_ZERO(&writeFds);
        FD_SET(sock, &writeFds);
#ifdef _WIN32
        const int ready = select(0, nullptr, &writeFds, nullptr, &timeout);
#else
        const int ready = select(sock + 1, nullptr, &writeFds, nullptr, &timeout);
#endif
        if (ready < 0)
            return false;
        if (ready == 0)
            continue;

        int error = 0;
#ifdef _WIN32
        int errorSize = sizeof(error);
#else
        socklen_t errorSize = sizeof(error);
#endif
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                       reinterpret_cast<char*>(&error), &errorSize) != 0 || error != 0)
            return false;
        if (!set_non_blocking(sock, false))
            return false;
        return configure_socket_io_timeouts(sock);
    }
    return false;
}

socket_t connect_to_target_worker(const std::string& host, uint16_t port,
                                  const std::shared_ptr<std::atomic_bool>& cancelled,
                                  std::chrono::steady_clock::time_point deadline)
{
    if(host.empty() || port == 0 || cancelled->load())
    {
        return INVALID_SOCKET_VALUE;
    }

    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const std::string port_string = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_string.c_str(), &hints, &res) != 0)
    {
        return INVALID_SOCKET_VALUE;
    }

    std::vector<addrinfo*> candidates;
    for (addrinfo* current = res; current != nullptr; current = current->ai_next)
        if (current->ai_family == AF_INET)
            candidates.push_back(current);
    for (addrinfo* current = res; current != nullptr; current = current->ai_next)
        if (current->ai_family != AF_INET)
            candidates.push_back(current);

    socket_t connected = INVALID_SOCKET_VALUE;
    std::size_t remainingCandidates = candidates.size();
    for (addrinfo* current : candidates)
    {
        const auto now = std::chrono::steady_clock::now();
        if (cancelled->load() || now >= deadline)
            break;
        const auto candidateDeadline = now + (deadline - now) / remainingCandidates;
        --remainingCandidates;
        socket_t sockfd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (sockfd == INVALID_SOCKET_VALUE)
            continue;

        if (connect_with_timeout(sockfd, current->ai_addr,
                                 static_cast<socklen_t>(current->ai_addrlen), *cancelled,
                                 candidateDeadline))
        {
            if (cancelled->load())
                close_socket(sockfd);
            else
                connected = sockfd;
            break;
        }

        close_socket(sockfd);
    }

    freeaddrinfo(res);
    return connected;
}

socket_t connect_to_target(const std::string& host, uint16_t port)
{
    auto cancelled = std::make_shared<std::atomic_bool>(false);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(SOCKS_IO_TIMEOUT_MS - 250);
    std::packaged_task<socket_t()> task([host, port, cancelled, deadline]() {
#ifdef _WIN32
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
            return INVALID_SOCKET_VALUE;
#endif
        const socket_t result = connect_to_target_worker(host, port, cancelled, deadline);
#ifdef _WIN32
        WSACleanup();
#endif
        return result;
    });
    bool accepted = false;
    auto future = connectWorkerPool().submit(std::move(task), accepted);
    if (!accepted)
    {
        cancelled->store(true);
        return INVALID_SOCKET_VALUE;
    }
    if (future.wait_for(std::chrono::milliseconds(SOCKS_IO_TIMEOUT_MS)) !=
        std::future_status::ready)
    {
        cancelled->store(true);
        return INVALID_SOCKET_VALUE;
    }
    return future.get();
}


socket_t connect_to_host(uint32_t ip, uint16_t port)
{
    return connect_to_target(int_to_str(ip), port);
}


//
// SocksTunnelClient
// 
SocksTunnelClient::SocksTunnelClient(int id)
: m_id(id)
, m_socketRuntimeReady(true)
, m_dataSocketNonBlocking(false)
{
    m_internalBuffer.resize(BUF_SIZE);

#ifdef __linux__
#elif _WIN32
    WSADATA wsaData;
    m_socketRuntimeReady = WSAStartup(MAKEWORD(2,2), &wsaData) == 0;
#endif
}


SocksTunnelClient::~SocksTunnelClient()
{
    m_clientfd.reset();
#ifdef _WIN32
    if (m_socketRuntimeReady)
        WSACleanup();
#endif
}


int SocksTunnelClient::init(uint32_t ip_dst, uint16_t port)
{
    if (!m_socketRuntimeReady)
        return 0;
#ifdef __linux__
    signal(SIGPIPE, sig_handler);
#elif _WIN32

#endif

    m_clientfd.reset(connect_to_host(ip_dst, ntohs(port)));
    if(m_clientfd.get() == INVALID_SOCKET_VALUE)
    {
        return 0;
    }

    return 1;
}


int SocksTunnelClient::initHostname(const std::string& hostname, uint16_t port)
{
    if (!m_socketRuntimeReady)
        return 0;
#ifdef __linux__
    signal(SIGPIPE, sig_handler);
#elif _WIN32

#endif

    m_clientfd.reset(connect_to_target(hostname, ntohs(port)));
    if(m_clientfd.get() == INVALID_SOCKET_VALUE)
    {
        return 0;
    }

    return 1;
}


int SocksTunnelClient::process(const std::string& dataIn, std::string& dataOut)
{
    if (!m_dataSocketNonBlocking)
    {
        if (!set_socket_non_blocking(m_clientfd.get(), true))
            return -1;
        m_dataSocketNonBlocking = true;
    }

    const BufferedSendStatus sendStatus = m_pendingWrite.appendAndFlush(m_clientfd.get(), dataIn);
    if (sendStatus == BufferedSendStatus::Error || sendStatus == BufferedSendStatus::Overflow)
        return -1;

    DrainStatus status = readAllAvailableNow_(m_clientfd.get(), dataOut, 0);
    if(status == DrainStatus::Error || status == DrainStatus::Disconnected)
        return -1;

    return 1;
}
