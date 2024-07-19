#pragma once

#ifdef __linux__
#elif _WIN32
#include <winsock2.h>
#include <windows.h>
#endif


#define BUF_SIZE 256

// Command constants 
#define CMD_CONNECT         1
#define CMD_BIND            2
#define CMD_UDP_ASSOCIATIVE 3

// Address type constants 
#define ATYP_IPV4   1
#define ATYP_DNAME  3
#define ATYP_IPV6   4

// Connection methods 
#define ALLOW_NO_AUTH
#define METHOD_NOAUTH       0
#define METHOD_AUTH         2
#define METHOD_NOTAVAILABLE 0xff

// Responses
#define RESP_SUCCEDED       0
#define RESP_GEN_ERROR      1

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
}


inline int recv_sock(int sock, char *buffer, uint32_t size) 
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


inline int send_sock(int sock, const char *buffer, uint32_t size) 
{
    int index = 0, ret;
    while(size) 
    {
        if((ret = send(sock, &buffer[index], size, 0)) <= 0)
            return (!ret) ? index : -1;
        index += ret;
        size -= ret;
    }
    return index;
}


inline bool readAllDataFromSocket(int sockfd, char* buffer, int &bytes_received)
{
    fd_set readfds;
    bytes_received=0;
    struct timeval timeout;

    // Initialize the file descriptor set
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    // TODO how to Set timeout, now 10ms
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);

    bool isDataAvailable=false;
    if (activity < 0) 
    {
        perror("select error");
    } else if (activity == 0) 
    {
        printf("Timeout: No data available to read\n");
    } 
    else 
    {
        if (FD_ISSET(sockfd, &readfds)) 
        {
            isDataAvailable=true;
            // Data is available to read
            bytes_received = recv(sockfd, buffer, BUF_SIZE, 0);
            if (bytes_received == -1) 
            {
                perror("recv failed");
            } 
            else if (bytes_received == 0) 
            {
                printf("Connection closed by peer\n");
            } 
            else 
            {
                printf("Received: %d\n", bytes_received);
            }
        }
    }

    return isDataAvailable;
}