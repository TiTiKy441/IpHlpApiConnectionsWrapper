# IpHlpApiConnectionsWrapper
This is a C# wrapper for iphlpapi.dll

It was made for the purpose of retrieving all TCP/UDP connections of any type (process/module/basic, ipv6/ipv4) as fast as possible. Speed is a key goal.

Available functions and methods:
1. `SetBufferSize(int newSize)`
   
   Sets buffer size. Reallocates internal buffer for storing data between iphlpapi.dll and the wrapper.
3. `GetTcpTable(AddressFamily networkType, TcpTableClass tcpTable, bool sortedOrder = false)`

   Retrieves information about all tcp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)
5. `GetUdpTable(AddressFamily networkType, UdpTableClass udpTable, bool sortedOrder = false))`

   Retrieves information about all udp connections of any type (process/module/basic) in the specified network layer (ipv4/ipv6)

## Example

```
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

    tcp4ProcessRecordList = wrapper.GetTcpTable(AddressFamily.InterNetwork, TcpTableClass.TCP_TABLE_OWNER_PID_ALL).Cast<Tcp4ProcessRecord>().ToList();
    tcp6ModuleRecordList = wrapper.GetTcpTable(AddressFamily.InterNetworkV6, TcpTableClass.TCP_TABLE_OWNER_MODULE_ALL).Cast<Tcp6ModuleRecord>().ToList();
}
```
