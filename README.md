# IpHlpApiConnectionsWrapper
This is a performance focused C# wrapper for iphlpapi.dll. Works on .NET 6.0

It was made for the purpose of retrieving all TCP/UDP connections of any type (process/module/basic, ipv6/ipv4) as fast as possible. Speed is a key goal.

Available functions and methods:
1. `SetBufferSize(int newSize)`
   
   Sets buffer size. Reallocates internal buffer for storing data between iphlpapi.dll and the wrapper.
2. `GetTcpTable(AddressFamily networkType, TcpTableClass tcpTable, bool sortedOrder = false)`

   Retrieves information about all tcp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)
3. `GetUdpTable(AddressFamily networkType, UdpTableClass udpTable, bool sortedOrder = false)`

   Retrieves information about all udp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)
4. `GetIpNetTableRecords(bool sortedOrder = false)`

   Retrieves information about all ip addresses in the network and their associated physical addresses




5. `GetTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)`

   Retrieves information about all tcp ipv4 connections of any type (process/module/basic)
6. `GetProcessTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)`

   Retrieves information about all tcp ipv4 process connections (all/listener/connections)
7. `GetModuleTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)`

   Retrieves information about all tcp ipv4 module connections (all/listener/connections)
8. `GetBasicTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)`

   Retrieves information about all tcp ipv4 basic connections (all/listener/connections)
9. `GetTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)`

   Retrieves information about all tcp ipv6 connections of any type (process/module/basic)
10. `GetProcessTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)`

    Retrieves information about all tcp ipv6 process connections (all/listener/connections)
11. `GetModuleTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)`

    Retrieves information about all tcp ipv6 module connections (all/listener/connections)
12. `GetUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)`

    Retrieves information about all udp ipv4 connections of any type (process/module/basic)
13. `GetProcessUdp4Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)`

    Retrieves information about all udp ipv4 process connections
14. `GetModuleUdp4Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)`

    Retrieves information about all udp ipv4 module connections
15. `GetBasicUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)`

    Retrieves information about all udp ipv4 basic connections
16. `GetUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)`

    Retrieves information about all udp ipv6 connections of any type (basic/module/process)
17. `GetProcessUdp6Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)`

    Retrieves information about all udp ipv6 process connections
18. `GetModuleUdp6Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)`

    Retrieves information about all udp ipv6 module connections
19. `GetBasicUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)`

    Retrieves information about all udp ipv6 basic connections
    
## Example

```C#
using(IpHelpApiWrapper wrapper = new IpHelpApiWrapper())
{
    List<Tcp4ProcessRecord> tcp4ProcessRecordList = wrapper.GetProcessTcp4Connections();
    List<Tcp4ModuleRecord> tcp4ModuleRecordList = wrapper.GetModuleTcp4Connections();
    List<Tcp4Record> tcp4BasicRecordList = wrapper.GetBasicTcp4Connections();
    List<Udp4ProcessRecord> udp4ProcessRecordList = wrapper.GetProcessUdp4Connections();
    List<Udp4ModuleRecord> udp4ModuleRecordList = wrapper.GetModuleUdp4Connections();
    List<Udp4Record> udp4BasicRecordList = wrapper.GetBasicUdp4Connections();
    List<Tcp6ProcessRecord> tcp6ProcessRecordList = wrapper.GetProcessTcp6Connections();
    List<Tcp6ModuleRecord> tcp6ModuleRecordList = wrapper.GetModuleTcp6Connections();
    List<Udp6ProcessRecord> udp6ProcessRecordList = wrapper.GetProcessUdp6Connections();
    List<Udp6ModuleRecord> udp6ModuleRecordList = wrapper.GetModuleUdp6Connections();
    List<PhysicalAddressRecord> records = wrapper.GetIpNetTableRecords();

    tcp4ProcessRecordList = wrapper.GetTcpTable(AddressFamily.InterNetwork, TcpTableClass.ProcessConnections).Cast<Tcp4ProcessRecord>().ToList();
    tcp6ModuleRecordList = wrapper.GetTcpTable(AddressFamily.InterNetworkV6, TcpTableClass.ModuleConnections).Cast<Tcp6ModuleRecord>().ToList();
}
```

## Performance recomendations
If you want to get some fixed type of record, you should get it directly (for example `GetProcessTcp4Connections()`, `GetModuleUdp6Connections()`) instead of `GetTcpTable` or `GetUdpTable`

Using `LocalIPAddress` or `LocalEndPoint` property of any record type internally converts `LocalAddress`, `LocalPort`, `LocalScopeId` into an `IPAddress` or `IpEndPoint`. This takes some computing power. If you are developing a high performance application which is, for example, have to compare IP address to the processes IP addresses in bulk, you should consider converting the IP address into `uint` and only then compare it with the processes IP addresses. Same applies to `RemoteAddress` and `RemoteEndPoint`
