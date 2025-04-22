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

Available static functions:

1. `uint GetBestInterfaceIndex(uint address)` / `GetBestInterfaceIndex(IPAddress address)`

   Retrieves best network interface address index to the target ipv4 address

2. `NetworkInterface GetBestInterface4(IPAddress address, NetworkInterface[]? interfaces = null)`

   Retrieves best network interface to the target ipv4 address

3. `uint GetBestInterfaceIndexEx(IPAddress address)`

   Retrieves best network interface address index to the target ipv4/ipv6 address

4. `NetworkInterface GetBestInterface6(IPAddress address, NetworkInterface[]? interfaces = null)`

   Retrieves best network inteface to the target ipv6 address

5. `NetworkInterface GetBestInterface(IPAddress address, NetworkInterface[]? interfaces = null)`

   Retrieves best network interface to the target ipv4/ipv6 address

6. `byte[] SendARP(uint destionationAddress, uint sourceAddress = 0)`

   Resolves PhysicalAddress (in byte[]) by sending ARP request to the target or by getting the PhysicalAddress from the ARP entries list 

7. `PhysicalAddress SendARP(IPAddress destAddress, IPAddress? srcAddress = null)`

   Resolves PhysicalAddress by sending ARP request to the target or by getting the PhysicalAddress from the ARP entries list

## Examples

Using freshly created wrapper:

```C#
using(IpHelpApiWrapper wrapper = new IpHelpApiWrapper())
{
   Tcp4ProcessRecord[] tcp4ProcessRecordList = wrapper.GetProcessTcp4Connections();
   Tcp4ModuleRecord[] tcp4ModuleRecordList = wrapper.GetModuleTcp4Connections();
   Tcp4Record[] tcp4BasicRecordList = wrapper.GetBasicTcp4Connections();
   Udp4ProcessRecord[] udp4ProcessRecordList = wrapper.GetProcessUdp4Connections();
   Udp4ModuleRecord[] udp4ModuleRecordList = wrapper.GetModuleUdp4Connections();
   Udp4Record[] udp4BasicRecordList = wrapper.GetBasicUdp4Connections();
   Tcp6ProcessRecord[] tcp6ProcessRecordList = wrapper.GetProcessTcp6Connections();
   Tcp6ModuleRecord[] tcp6ModuleRecordList = wrapper.GetModuleTcp6Connections();
   Udp6ProcessRecord[] udp6ProcessRecordList = wrapper.GetProcessUdp6Connections();
   Udp6ModuleRecord[] udp6ModuleRecordList = wrapper.GetModuleUdp6Connections();
   PhysicalAddressRecord[] ipNetRecordList = wrapper.GetIpNetTableRecords();

   tcp4ProcessRecordList = wrapper.GetTcpTable(AddressFamily.InterNetwork, TcpTableClass.ProcessConnections).Cast<Tcp4ProcessRecord>().ToArray();
   tcp6ModuleRecordList = wrapper.GetTcpTable(AddressFamily.InterNetworkV6, TcpTableClass.ModuleConnections).Cast<Tcp6ModuleRecord>().ToArray();
}
```

Using shared wrapper instance:
```C#
Tcp4ProcessRecord[] tcp4ProcessRecordList = IpHelpApiWrapper.Shared.GetProcessTcp4Connections();
Tcp4ModuleRecord[] tcp4ModuleRecordList = IpHelpApiWrapper.Shared.GetModuleTcp4Connections();
Tcp4Record[] tcp4BasicRecordList = IpHelpApiWrapper.Shared.GetBasicTcp4Connections();
Udp4ProcessRecord[] udp4ProcessRecordList = IpHelpApiWrapper.Shared.GetProcessUdp4Connections();
Udp4ModuleRecord[] udp4ModuleRecordList = IpHelpApiWrapper.Shared.GetModuleUdp4Connections();
Udp4Record[] udp4BasicRecordList = IpHelpApiWrapper.Shared.GetBasicUdp4Connections();
Tcp6ProcessRecord[] tcp6ProcessRecordList = IpHelpApiWrapper.Shared.GetProcessTcp6Connections();
Tcp6ModuleRecord[] tcp6ModuleRecordList = IpHelpApiWrapper.Shared.GetModuleTcp6Connections();
Udp6ProcessRecord[] udp6ProcessRecordList = IpHelpApiWrapper.Shared.GetProcessUdp6Connections();
Udp6ModuleRecord[] udp6ModuleRecordList = IpHelpApiWrapper.Shared.GetModuleUdp6Connections();
PhysicalAddressRecord[] ipNetRecordList = IpHelpApiWrapper.Shared.GetIpNetTableRecords();

tcp4ProcessRecordList = IpHelpApiWrapper.Shared.GetTcpTable(AddressFamily.InterNetwork, TcpTableClass.ProcessConnections).Cast<Tcp4ProcessRecord>().ToArray();
tcp6ModuleRecordList = IpHelpApiWrapper.Shared.GetTcpTable(AddressFamily.InterNetworkV6, TcpTableClass.ModuleConnections).Cast<Tcp6ModuleRecord>().ToArray();
```

Using static functions:
```C#
//Retrieves main network interface
public static NetworkInterface GetMainNetworkInterface()
{
    return IpHelpApiWrapper.GetBestInterface4(IPAddress.Any);
}

//
public static PhysicalAddress GetGatewayPhysicalAddress()
{
    IPAddress targetAddress = IpHelpApiWrapper.GetBestInterface4(IPAddress.Any).GetIPProperties().GatewayAddresses.Last().Address;.;
    PhysicalAddressRecord[] records = IpHelpApiWrapper.Shared.GetIpNetTableRecords(); // List of ip addresses and their physical addresses
    PhysicalAddress? found = Array.Find(records, x => x.IpAddress.Equals(targetAddress) && (x.NetType != IpNetType.Invalid))?.PhysicalAddress;
    if (found == null) throw new AggregateException("Gateway address was not found in the table");
    return found;
```

## Performance recomendations
If you want to get some fixed type of record, you should get it directly (for example `GetProcessTcp4Connections()`, `GetModuleUdp6Connections()`) instead of `GetTcpTable` or `GetUdpTable`

Using `LocalIPAddress` or `LocalEndPoint` property of any record type internally converts `LocalAddress`, `LocalPort`, `LocalScopeId` into an `IPAddress` or `IpEndPoint`. This takes some computing power. If you are developing a high performance application which is, for example, have to compare IP address to the processes IP addresses in bulk, you should consider converting the IP address into `uint` and only then compare it with the processes IP addresses. Same applies to `RemoteAddress` and `RemoteEndPoint`
