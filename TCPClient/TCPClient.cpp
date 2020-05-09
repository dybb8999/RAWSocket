// TCPClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Mstcpip.h>
#include <array>
#pragma comment(lib, "Ws2_32.lib")


typedef struct _iphdr //定义IP报头 
{
    uint32_t h_len : 4; //4位首部长度
    uint32_t ver : 4; //4位IP版本号 
    uint32_t tos : 8;
    uint32_t total_len : 16;
    uint32_t ident : 16;
    uint32_t frag_and_flags : 16;
    uint32_t ttl : 8;
    uint32_t proto : 8;
    uint32_t checksum : 16;
    uint32_t sourceIP : 32;
    uint32_t destIP : 32;
} IP_HEADER, * PIP_HEADER;

int main(int argc, char** argv)
{
    std::string strFromAddress = "";
    std::string strToAddress = "";
    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "-f") == 0)
        {
            strFromAddress = argv[i + 1];
            i += 1;
        }
        else if (_stricmp(argv[i], "-t") == 0)
        {
            strToAddress = argv[i + 1];
            i += 1;
        }
    }

    if (strFromAddress == "" || strToAddress == "")
    {
        printf("TCPClient -f 192.168.1.1 -t 192.168.1.2\n");
        return 0;
    }

    int nStatus = 0;
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sListen = INVALID_SOCKET;
    do
    {
        sListen = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (sListen == INVALID_SOCKET)
        {
            break;
        }

        int on = 1;
        setsockopt(sListen, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on));

        uint8_t buff[1024] = { 0 };
        sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        inet_pton(AF_INET, strToAddress.c_str(), &addr.sin_addr);
        int nSize = sizeof(addr);
        //nStatus = connect(sListen, (sockaddr*)&addr, sizeof(addr));

        //int value = RCVALL_IPLEVEL;
        //DWORD out = 0;
        //nStatus = WSAIoctl(sListen, SIO_RCVALL, &value, sizeof(value), NULL, 0, &out, NULL, NULL);
        //if (nStatus == SOCKET_ERROR) {
        //    fprintf(stderr, "WSAIoctl() failed: %u", WSAGetLastError());
        //    exit(-1);
        //}
        constexpr char flag[] = "ABCDEFGHIJKLMN";
        char strIP[64] = { 0 };

        std::array<uint8_t, sizeof(flag) + sizeof(IP_HEADER)> buff2;
        memset(buff2.data(), 0, buff2.size());
        uint8_t* pOffset = buff2.data();

        PIP_HEADER pHeader = (PIP_HEADER)pOffset;
        int nSource = 0;
        inet_pton(AF_INET, strFromAddress.c_str(), &nSource);

        int nDest = 0;
        inet_pton(AF_INET, strToAddress.c_str(), &nDest);

        pHeader->h_len = 5;
        pHeader->ver = 4;
        pHeader->total_len = buff2.size();
        pHeader->ident = 0xAAAA;
        pHeader->frag_and_flags = htons(0x4000);
        pHeader->ttl = 0x80;
        pHeader->proto = IPPROTO_RAW;
        pHeader->checksum = 0;
        pHeader->destIP = nDest;
        pHeader->sourceIP = nSource;
        pOffset += sizeof(IP_HEADER);
        
        memcpy(pOffset, flag, sizeof(flag));
        //nStatus = send(sListen, (const char*)buff2.data(), buff2.size(), 0);
        nStatus = sendto(sListen, (const char*)buff2.data(), buff2.size(), 0, (sockaddr*)&addr, sizeof(addr));
        
        
    } while (false);

    if (sListen != INVALID_SOCKET)
    {
        closesocket(sListen);
        sListen = INVALID_SOCKET;
    }
}
