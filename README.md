# IpHlpApiConnectionsWrapper
This is a C# wrapper for iphlpapi.dll

It was made for the purpose of retrieving all TCP/UDP connections of any type (process/module/basic, ipv6/ipv4)

Available functions and methods:
1. `SetBufferSize(int newSize)`
   
   Sets buffer size. Reallocates internal buffer for storing data between iphlpapi.dll and the wrapper.
3. `GetTcpTable(NetworkType networkType, TcpTableClass tcpTable, bool sortedOrder = false)`

   Retrieves information about all tcp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)
5. `GetUdpTable(NetworkType networkType, UdpTableClass udpTable, bool sortedOrder = false))`

   Retrieves information about all udp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)
