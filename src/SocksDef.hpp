#pragma once

#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#elif _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <atomic>
#include <chrono>

static constexpr std::size_t BUF_SIZE = 2048;
static constexpr int SOCKS_IO_TIMEOUT_MS = 5000;

#ifdef _WIN32
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
using socket_t = int;
static constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

// Command constants
enum class Command : uint8_t
{
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3
};

// Address type constants
enum class AddressType : uint8_t
{
    IPv4 = 1,
    DName = 3,
    IPv6 = 4
};

// Connection methods
constexpr bool ALLOW_NO_AUTH = true;
enum class Method : uint8_t
{
    NoAuth = 0,
    Auth = 2,
    NotAvailable = 0xff
};

// Responses
enum class Response : uint8_t
{
    Succeeded = 0,
    Succeded = Succeeded,
    GenError = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8
};

// windows compatibility
#ifndef _SSIZE_T_DEFINED
#ifdef  _WIN64
typedef unsigned __int64    ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2 
#endif


// handle sig_pipe that can crash the app otherwise
inline void sig_handler(int signum)
{
    (void)signum;
}

class SocketHandle
{
public:
    SocketHandle() : m_fd(INVALID_SOCKET_VALUE) {}
    explicit SocketHandle(socket_t fd) : m_fd(fd) {}
    ~SocketHandle() { reset(); }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    SocketHandle(SocketHandle&& other) noexcept
        : m_fd(other.m_fd.exchange(INVALID_SOCKET_VALUE)) {}
    SocketHandle& operator=(SocketHandle&& other) noexcept
    {
        if(this != &other)
        {
            reset();
            m_fd.store(other.m_fd.exchange(INVALID_SOCKET_VALUE));
        }
        return *this;
    }
    socket_t get() const { return m_fd.load(); }
    void reset(socket_t fd = INVALID_SOCKET_VALUE)
    {
        const socket_t old = m_fd.exchange(fd);
        if(old != INVALID_SOCKET_VALUE)
        {
#ifdef __linux__
            ::shutdown(old, SHUT_RDWR);
            ::close(old);
#elif _WIN32
            ::shutdown(old, SHUT_RDWR);
            ::closesocket(old);
#endif
        }
    }
private:
    std::atomic<socket_t> m_fd;
};

inline bool configure_socket_io_timeouts(socket_t sock, int timeoutMs = SOCKS_IO_TIMEOUT_MS)
{
#ifdef _WIN32
    const DWORD timeout = static_cast<DWORD>(timeoutMs);
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0 &&
           setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
#else
    timeval timeout{};
    timeout.tv_sec = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
           setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0;
#endif
}


inline int recv_sock(socket_t sock, char *buffer, uint32_t size)
{
    int index = 0, ret;
    while(size) 
    {
        if((ret = recv(sock, &buffer[index], size, 0)) <= 0)
            return (!ret) ? index : -1;

        index += ret;
        size -= ret;
    }
    return index;
}


inline int send_sock(socket_t sock, const char *buffer, uint32_t size)
{
    uint32_t index = 0;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(SOCKS_IO_TIMEOUT_MS);
    while(size)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return -1;

        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(remaining.count() / 1000000);
        timeout.tv_usec = static_cast<long>(remaining.count() % 1000000);

        fd_set writeFds;
        FD_ZERO(&writeFds);
        FD_SET(sock, &writeFds);
#ifdef _WIN32
        const int ready = select(0, nullptr, &writeFds, nullptr, &timeout);
#else
        const int ready = select(sock + 1, nullptr, &writeFds, nullptr, &timeout);
#endif
        if (ready <= 0)
            return -1;

        const int chunk = static_cast<int>(std::min<uint32_t>(size, 16 * 1024));
#ifdef __linux__
        const int ret = static_cast<int>(send(sock, &buffer[index], chunk, MSG_NOSIGNAL));
#else
        const int ret = send(sock, &buffer[index], chunk, 0);
#endif
        if(ret <= 0)
            return ret == 0 ? static_cast<int>(index) : -1;
        index += static_cast<uint32_t>(ret);
        size -= static_cast<uint32_t>(ret);
    }
    return static_cast<int>(index);
}

// Read all data that is currently available *now* (best-effort), without changing blocking mode.
// - Waits up to timeout_ms for the socket to become readable.
// - Then drains using non-blocking recv *per call*:
//    - Linux: uses MSG_DONTWAIT (does not toggle socket flags)
//    - Windows: uses recv(..., MSG_PEEK) + ioctlsocket(FIONREAD) to avoid blocking
//
// Notes:
// - This is "drain available bytes", NOT "read a full message".
// - Uses a max_bytes cap to prevent unbounded memory growth.

#include <string>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using sock_t = socket_t;
#else
  #include <poll.h>
  #include <sys/socket.h>
  #include <errno.h>
  using sock_t = socket_t;
#endif

enum class DrainStatus { ReadSome, NoData, Disconnected, Error, Truncated };

inline DrainStatus readAllAvailableNow_(sock_t s, std::string& out, int timeout_ms = 0, size_t max_bytes = 262144)
{
    out.clear();
    if (max_bytes == 0)
        return DrainStatus::NoData;

    // Wait for readability (poll/WSAPoll). This does not change socket mode.
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = POLLRDNORM; // readable
    int prc = WSAPoll(&pfd, 1, timeout_ms);
    if (prc == SOCKET_ERROR)
        return DrainStatus::Error;
    if (prc == 0)
        return DrainStatus::NoData;
#else
    pollfd pfd{};
    pfd.fd = s;
    pfd.events = POLLIN;
    int prc;
    do {
        prc = poll(&pfd, 1, timeout_ms);
    } while (prc < 0 && errno == EINTR);
    if (prc < 0)
        return DrainStatus::Error;
    if (prc == 0)
        return DrainStatus::NoData;
#endif

    DrainStatus status = DrainStatus::NoData;
    char buf[4096];

#ifdef _WIN32
    // Windows: without switching to non-blocking, we must avoid a recv() that could block.
    // Strategy:
    //  1) Query bytes available with FIONREAD.
    //  2) Read exactly that many bytes (bounded by max_bytes) in chunks.
    u_long avail = 0;
    if (ioctlsocket(s, FIONREAD, &avail) != 0)
        return DrainStatus::Error;

    if (avail == 0)
    {
        // Either no data, or a close is pending. Probe with MSG_PEEK (safe after poll).
        char tmp;
        int n = recv(s, &tmp, 1, MSG_PEEK);
        if (n == 0)  return DrainStatus::Disconnected;
        if (n < 0)   return DrainStatus::Error;
        return DrainStatus::NoData;
    }

    size_t to_read = std::min<size_t>((size_t)avail, max_bytes);
    out.reserve(std::min<size_t>(to_read, 64 * 1024));

    size_t read_total = 0;
    while (read_total < to_read)
    {
        int want = (int)std::min<size_t>(sizeof(buf), to_read - read_total);
        int n = recv(s, buf, want, 0);
        if (n > 0)
        {
            out.append(buf, n);
            read_total += (size_t)n;
            status = DrainStatus::ReadSome;
            continue;
        }
        if (n == 0)
            return (status == DrainStatus::ReadSome) ? DrainStatus::ReadSome : DrainStatus::Disconnected;

        return (status == DrainStatus::ReadSome) ? DrainStatus::ReadSome : DrainStatus::Error;
    }

    if ((size_t)avail > max_bytes)
        return DrainStatus::Truncated;

    return status;

#else
    // Linux: MSG_DONTWAIT makes this recv call non-blocking without toggling flags.
    out.reserve(std::min<size_t>(max_bytes, 64 * 1024));

    while (out.size() < max_bytes)
    {
        size_t room = max_bytes - out.size();
        int want = (int)std::min<size_t>(room, sizeof(buf));

        ssize_t n = recv(s, buf, want, MSG_DONTWAIT);
        if (n > 0)
        {
            out.append(buf, (size_t)n);
            status = DrainStatus::ReadSome;
            continue;
        }
        if (n == 0)
            return (status == DrainStatus::ReadSome) ? DrainStatus::ReadSome : DrainStatus::Disconnected;

        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;

        return (status == DrainStatus::ReadSome) ? DrainStatus::ReadSome : DrainStatus::Error;
    }

    if (out.size() >= max_bytes)
        return DrainStatus::Truncated;

    return status;
#endif
}
