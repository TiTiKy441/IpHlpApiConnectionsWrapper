# IpHlpApiConnectionsWrapper
This is a C# wrapper for iphlpapi.dll

It was made for the purpose of retrieving all TCP/UDP process connections as fast as possible

Available functions and methods:
1. `SetBufferSize(int newSize)`
   
   Sets buffer size. Reallocates internal buffer for storing data between iphlpapi.dll and the wrapper.
3. `GetAllTcpConnections(NetworkType network)`

   Retrieves information about all tcp connections owned by processes in the specified network layer (ipv4/ipv6)
5. `GetAllUdpConnections(NetworkType network)`

   Retrieves information about all udp connections owned by processes in the specified network layer (ipv4/ipv6)
