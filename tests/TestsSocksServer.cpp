#include <iostream>
#include <string>
#include <chrono>
#include <thread>

#include "SocksServer.hpp"
#include "SocksTunnelClient.hpp"


int main(int argc, char *argv[]) 
{
    SocksServer socksServer(1080);
    socksServer.launch();

    
    while(1)
    {
        for(int i=0; i<socksServer.m_socksTunnelServers.size(); i++)
        {
            std::cout << "main loop idx " << std::to_string(i) << std::endl;
            if(socksServer.m_socksTunnelServers[i]!=nullptr)
            {
                std::cout << "GO " << std::to_string(i) << std::endl;

                uint32_t ip = socksServer.m_socksTunnelServers[i]->getIpDst();
                uint16_t port = socksServer.m_socksTunnelServers[i]->getPort();

                SocksTunnelClient socksTunnelClient;
                socksTunnelClient.init(ip, port);

                socksServer.m_socksTunnelServers[i]->finishHandshack();

                std::string dataIn;
                std::string dataOut;
                while(1)
                {
                    int res = socksServer.m_socksTunnelServers[i]->process(dataIn, dataOut);
                    if(res<=0)
                        break;

                    res = socksTunnelClient.process(dataOut, dataIn);
                    if(res<=0)
                        break;
                }

                std::cout << "End    " << std::to_string(i) << std::endl;

                socksServer.m_socksTunnelServers[i].reset(nullptr);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    return 0;
}


