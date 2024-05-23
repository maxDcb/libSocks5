#pragma once


class SocksTunnelClient
{
    public:
        SocksTunnelClient();
        ~SocksTunnelClient(); 

        int init(uint32_t ip_dst, uint16_t port);
        int process(std::string& dataIn, std::string& dataOut);

    private:
        int m_clientfd;

        std::string m_internalBuffer;
};