#include <cstring>


#include <signal.h>

#ifdef __linux__
#include <unistd.h>
#include <netdb.h>
#elif _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <iostream>
#include <string>
#include <sstream>

#include "SocksTunnelClient.hpp"
#include "SocksDef.hpp"


using namespace std;


#ifdef __linux__

class Lock 
{
    pthread_mutex_t mutex;
public:
    Lock() 
    {
        pthread_mutex_init(&mutex, NULL);
    }
  
    ~Lock() 
    {
        pthread_mutex_destroy(&mutex);
    }
    
    inline void lock() 
    {
        pthread_mutex_lock(&mutex);
    }
    
    inline void unlock() 
    {
        pthread_mutex_unlock(&mutex);
    }
};


Lock get_host_lock;

#elif _WIN32

#endif


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


int connect_to_host(uint32_t ip, uint16_t port) 
{
    
    struct sockaddr_in serv_addr;
    struct hostent *server;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        // int errorsocket = WSAGetLastError();
        // std::cout << "errorsocket return code " << errorsocket << std::endl;
        return -1;
    }

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    std::string ip_string = int_to_str(ip);

#ifdef __linux__   
    
    get_host_lock.lock();
    server = gethostbyname(ip_string.c_str());
    if(!server) 
    {
        get_host_lock.unlock();
        return -1;
    }
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    get_host_lock.unlock();

#elif _WIN32

    inet_pton(AF_INET, ip_string.c_str(), &serv_addr.sin_addr.s_addr);

#endif
    
    serv_addr.sin_port = htons(port);

    return !connect(sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) ? sockfd : -1;
}


//
// SocksTunnelClient
// 
SocksTunnelClient::SocksTunnelClient(int id)
: m_id(id)
{
    m_internalBuffer.resize(BUF_SIZE);

#ifdef __linux__
#elif _WIN32
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
}


SocksTunnelClient::~SocksTunnelClient()
{
    shutdown(m_clientfd, SHUT_RDWR);

#ifdef __linux__
    close(m_clientfd);    
#elif _WIN32
    WSACleanup();
    closesocket(m_clientfd);    
#endif
}


int SocksTunnelClient::init(uint32_t ip_dst, uint16_t port)
{
#ifdef __linux__
    signal(SIGPIPE, sig_handler); 
#elif _WIN32
     
#endif

    m_clientfd = connect_to_host(ip_dst, ntohs(port));
    if(m_clientfd == -1)
    {
        return 0;
    }

    return 1;
}


int SocksTunnelClient::process(const std::string& dataIn, std::string& dataOut)
{
    if(dataIn.size()>0)
        send_sock(m_clientfd, dataIn.data(), dataIn.size());

    int bytes_received;
    bool isDataAvailable;

    isDataAvailable = readAllDataFromSocket(m_clientfd, &m_internalBuffer[0], bytes_received);

    std::cout << "isDataAvailable " << isDataAvailable << " " << "bytes_received " << bytes_received << std::endl;

    if(isDataAvailable && bytes_received <= 0)
        return -1;

    dataOut.assign(&m_internalBuffer[0], bytes_received);

    return 1;
}
