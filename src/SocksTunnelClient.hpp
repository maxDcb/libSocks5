#pragma once


class SocksTunnelClient
{
    public:
        SocksTunnelClient(int id=0);
        ~SocksTunnelClient(); 

        int init(uint32_t ip_dst, uint16_t port);
        int process(const std::string& dataIn, std::string& dataOut);

        int getId()
        {
            return m_id;
        }

    private:
        int m_id;
        int m_clientfd;

        std::string m_internalBuffer;
};