#pragma once

#include <string>

#include "SocksDef.hpp"

class SocksTunnelClient
{
    public:
        SocksTunnelClient(int id=0);
        ~SocksTunnelClient();

        int init(uint32_t ip_dst, uint16_t port);
        int initHostname(const std::string& hostname, uint16_t port);
        int process(const std::string& dataIn, std::string& dataOut);

        int getId()
        {
            return m_id;
        }

    private:
        int m_id;
        SocketHandle m_clientfd;
        bool m_socketRuntimeReady;

        std::string m_internalBuffer;
};
