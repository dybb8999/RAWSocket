// TCPServer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <WS2tcpip.h>
#include <Windows.h>
#include <Mstcpip.h>
#pragma comment(lib, "Ws2_32.lib")


typedef struct _iphdr //定义IP报头 
{
    uint32_t h_len : 4; //4位首部长度
    uint32_t ver : 4; //4位IP版本号 
    uint32_t tos : 8;
    uint32_t total_len : 16;
    uint32_t ident : 16;
    uint32_t frag_and_flags:16;
    uint32_t ttl:8;
    uint32_t proto:8;
    uint32_t checksum:16;
    uint32_t sourceIP:32;
    uint32_t destIP:32;
} IP_HEADER, *PIP_HEADER;

int main(int argc, const char** argv)
{
    std::string strListen = "";
    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "-ip") == 0)
        {
            strListen = argv[i+1];
        }
    }

    if (strListen == "")
    {
        printf_s("TCPServer -ip 127.0.0.1\n");
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
        inet_pton(AF_INET, strListen.c_str(), &addr.sin_addr);
        int nSize = sizeof(addr);
        nStatus = bind(sListen, (sockaddr*)&addr, sizeof(addr));

        int value = RCVALL_IPLEVEL;
        DWORD out = 0;
        nStatus = WSAIoctl(sListen, SIO_RCVALL, &value, sizeof(value), NULL, 0, &out, NULL, NULL);
        if (nStatus == SOCKET_ERROR) {
            fprintf(stderr, "WSAIoctl() failed: %u", WSAGetLastError());
            exit(-1);
        }

        char strIP[64] = { 0 };
        while (true)
        {
            memset(buff, 0, 1024);
            nStatus = recv(sListen, (char*)buff, 1024, 0);
            PIP_HEADER pIPHeader = (PIP_HEADER)buff;
            if (pIPHeader->proto != IPPROTO_RAW)
            {
                continue;
            }
            printf("-----------------------\n");
            
            printf("Protocol:%d\n", (int)pIPHeader->proto);
            uint32_t uSourceData = pIPHeader->sourceIP;
            inet_ntop(AF_INET, &uSourceData, strIP, 64);
            printf("Source:%s\n", strIP);

            uint32_t uDestData = pIPHeader->destIP;
            inet_ntop(AF_INET, &uDestData, strIP, 64);
            printf("Dest:%s\n", strIP);

            uint8_t* pOffset = buff + sizeof(IP_HEADER);
            for (int i = 0; i < 20; ++i)
            {
                printf("%02X ", pOffset[i]);
            }
            putchar('\n');
        }
        
        
        int a = 01;
    } while (false);

    if (sListen != INVALID_SOCKET)
    {
        closesocket(sListen);
        sListen = INVALID_SOCKET;
    }

    return 0;
}
