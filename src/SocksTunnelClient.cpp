#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

#include <iostream>
#include <string>
#include <sstream>

#include "SocksTunnelClient.hpp"
#include "SocksDef.hpp"


using namespace std;


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
        return -1;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    std::string ip_string = int_to_str(ip);
    
    get_host_lock.lock();
    server = gethostbyname(ip_string.c_str());
    if(!server) 
    {
        get_host_lock.unlock();
        return -1;
    }
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    get_host_lock.unlock();
    
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
}


SocksTunnelClient::~SocksTunnelClient()
{
    shutdown(m_clientfd, SHUT_RDWR);
    close(m_clientfd);    
}


int SocksTunnelClient::init(uint32_t ip_dst, uint16_t port)
{
    signal(SIGPIPE, sig_handler);

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

    ssize_t bytes_received;
    bool isDataAvailable;

    isDataAvailable = readAllDataFromSocket(m_clientfd, &m_internalBuffer[0], bytes_received);
    if(isDataAvailable && bytes_received <= 0)
        return -1;

    dataOut.assign(&m_internalBuffer[0], bytes_received);

    return 1;
}
