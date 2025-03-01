using System.Net;
using System.Runtime.InteropServices;

public class IpHelpApiWrapper
{

    [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

    public static int BufferSize { get; private set; } = 1048576; // 1 MByte

    private static IntPtr _buffer = Marshal.AllocHGlobal(BufferSize);

    private static readonly object _bufferLockObject = new();

    public static void SetBufferSize(int newSize)
    {
        lock (_bufferLockObject)
        {
            _buffer = Marshal.ReAllocHGlobal(_buffer, (IntPtr)newSize);
            BufferSize = newSize;
        }
    }

    #region TCP4 Functions

    public static List<Tcp4Record> GetTcp4Connections(bool sortedOrder = true, TcpTableClass tcpTable = TcpTableClass.TCP_TABLE_BASIC_ALL)
    {
        return tcpTable switch
        {
            TcpTableClass.TCP_TABLE_BASIC_ALL or TcpTableClass.TCP_TABLE_BASIC_LISTENER or TcpTableClass.TCP_TABLE_BASIC_CONNECTIONS => GetBasicTcp4Connections(sortedOrder, tcpTable),
            TcpTableClass.TCP_TABLE_OWNER_MODULE_ALL or TcpTableClass.TCP_TABLE_OWNER_MODULE_LISTENER or TcpTableClass.TCP_TABLE_OWNER_MODULE_CONNECTIONS => GetModuleTcp4Connections(sortedOrder, tcpTable).Cast<Tcp4Record>().ToList(),
            TcpTableClass.TCP_TABLE_OWNER_PID_ALL or TcpTableClass.TCP_TABLE_OWNER_PID_LISTENER or TcpTableClass.TCP_TABLE_OWNER_PID_CONNECTIONS => GetProcessTcp4Connections(sortedOrder, tcpTable).Cast<Tcp4Record>().ToList(),
            _ => throw new ArgumentException("Invalid argument: tcpTable"),
        };
    }

    #region GetProcessTcp4Connections()

    public static List<Tcp4ProcessRecord> GetProcessTcp4Connections(bool sortedOrder = true, TcpTableClass tcpTable = TcpTableClass.TCP_TABLE_OWNER_PID_ALL)
    {
        if (!(tcpTable is TcpTableClass.TCP_TABLE_OWNER_PID_ALL or TcpTableClass.TCP_TABLE_OWNER_PID_CONNECTIONS or TcpTableClass.TCP_TABLE_OWNER_PID_LISTENER)) throw new ArgumentException("GetProcessTcp4Connections() supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, tcpTable);

            HandleErrorCode(errorCode);

            return CreateTcp4ProcessRecordListFromIntPtr((IntPtr)((long)_buffer + 4), GetCurrentEntriesNum());
        }
    }

    private static List<Tcp4ProcessRecord> CreateTcp4ProcessRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 24;

        List<Tcp4ProcessRecord> records = new(num);

        byte[] managedArray = new byte[singleSize * num];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    state: (MibState)BitConverter.ToUInt32(managedArray, i + 0),
                    localAddress: BitConverter.ToUInt32(managedArray, i + 4),
                    localPort: GetPortFromBytes(managedArray[(i + 8)..(i + 12)]),
                    remoteAddress: BitConverter.ToUInt32(managedArray, i + 12),
                    remotePort: GetPortFromBytes(managedArray[(i + 16)..(i + 20)]),
                    pId: BitConverter.ToInt32(managedArray, i + 20)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleTcp4Connections()
    public static List<Tcp4ModuleRecord> GetModuleTcp4Connections(bool sortedOrder = true, TcpTableClass tcpTable = TcpTableClass.TCP_TABLE_OWNER_MODULE_ALL)
    {
        if (!(tcpTable is TcpTableClass.TCP_TABLE_OWNER_MODULE_ALL or TcpTableClass.TCP_TABLE_OWNER_MODULE_CONNECTIONS or TcpTableClass.TCP_TABLE_OWNER_MODULE_LISTENER)) throw new ArgumentException("GetModuleTcp4Connections() supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, tcpTable);

            HandleErrorCode(errorCode);

            return CreateTcp4ModuleRecordListFromIntPtr((IntPtr)((long)_buffer + 8), GetCurrentEntriesNum(), bufferSize - 4);
        }
    }

    private static List<Tcp4ModuleRecord> CreateTcp4ModuleRecordListFromIntPtr(IntPtr pointer, int num, int allocatedSize)
    {
        int singleSize = 160;

        List<Tcp4ModuleRecord> records = new(num);

        byte[] managedArray = new byte[allocatedSize];
        Marshal.Copy(pointer, managedArray, 0, allocatedSize);

        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    state: (MibState)BitConverter.ToUInt32(managedArray, i + 0),
                    localAddress: BitConverter.ToUInt32(managedArray, i + 4),
                    localPort: GetPortFromBytes(managedArray[(i + 8)..(i + 12)]),
                    remoteAddress: BitConverter.ToUInt32(managedArray, i + 12),
                    remotePort: GetPortFromBytes(managedArray[(i + 16)..(i + 20)]),
                    pId: BitConverter.ToInt32(managedArray, i + 20),
                    createTimestamp: BitConverter.ToInt64(managedArray, i + 24),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(managedArray.AsSpan()[(i + 32)..(i + 160)]).ToArray()
                )
            );
        }

        return records;
    }

    #endregion

    #region GetBasicTcp4Connections()

    public static List<Tcp4Record> GetBasicTcp4Connections(bool sortedOrder = true, TcpTableClass tcpTable = TcpTableClass.TCP_TABLE_BASIC_ALL)
    {
        if (!(tcpTable is TcpTableClass.TCP_TABLE_BASIC_ALL or TcpTableClass.TCP_TABLE_BASIC_CONNECTIONS or TcpTableClass.TCP_TABLE_BASIC_LISTENER)) throw new ArgumentException("GetBasicTcp4Connections() supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, tcpTable);

            HandleErrorCode(errorCode);

            return CreateTcp4BasicRecordListFromIntPtr((IntPtr)((long)_buffer + 4), GetCurrentEntriesNum());
        }
    }

    private static List<Tcp4Record> CreateTcp4BasicRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 20;

        List<Tcp4Record> records = new(num);

        byte[] managedArray = new byte[singleSize * num];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    state: (MibState)BitConverter.ToUInt32(managedArray, i + 0),
                    localAddress: BitConverter.ToUInt32(managedArray, i + 4),
                    localPort: GetPortFromBytes(managedArray[(i + 8)..(i + 12)]),
                    remoteAddress: BitConverter.ToUInt32(managedArray, i + 12),
                    remotePort: GetPortFromBytes(managedArray[(i + 16)..(i + 20)])
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    #region UDP4 Functions

    public static List<Udp4Record> GetUdp4Connections(bool sortedOrder = true, UdpTableClass udpTable = UdpTableClass.UDP_TABLE_BASIC)
    {
        return udpTable switch
        {
            UdpTableClass.UDP_TABLE_BASIC => GetBasicUdp4Connections(sortedOrder, udpTable),
            UdpTableClass.UDP_TABLE_OWNER_MODULE => GetModuleUdp4Connections(sortedOrder, udpTable).Cast<Udp4Record>().ToList(),
            UdpTableClass.UDP_TABLE_OWNER_PID => GetProcessUdp4Connections(sortedOrder, udpTable).Cast<Udp4Record>().ToList(),
            _ => throw new ArgumentException("Invalid argument: udpTable"),
        };
    }

    #region GetProcessUdp4Connections()

    public static List<Udp4ProcessRecord> GetProcessUdp4Connections(bool sortedOrder = true, UdpTableClass udpTable = UdpTableClass.UDP_TABLE_OWNER_PID)
    {
        if (!(udpTable is UdpTableClass.UDP_TABLE_OWNER_PID)) throw new ArgumentException("GetProcessUdp4Connections() supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, udpTable);

            HandleErrorCode(errorCode);

            return CreateUdp4ProcessRecordListFromIntPtr((IntPtr)((long)_buffer + 4), GetCurrentEntriesNum());
        }
    }

    private static List<Udp4ProcessRecord> CreateUdp4ProcessRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 12;

        List<Udp4ProcessRecord> records = new(num);

        byte[] managedArray = new byte[singleSize * num];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(managedArray, i + 0),
                    localPort: GetPortFromBytes(managedArray[(i + 4)..(i + 8)]),
                    pId: BitConverter.ToInt32(managedArray, i + 8)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleUdp4Connections()

    public static List<Udp4ModuleRecord> GetModuleUdp4Connections(bool sortedOrder = true, UdpTableClass udpTable = UdpTableClass.UDP_TABLE_OWNER_MODULE)
    {
        if (!(udpTable is UdpTableClass.UDP_TABLE_OWNER_MODULE)) throw new ArgumentException("GetModuleUdp4Connections() supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, udpTable);

            HandleErrorCode(errorCode);

            return CreateUdp4ModuleRecordListFromIntPtr((IntPtr)((long)_buffer + 8), GetCurrentEntriesNum(), bufferSize - 4);
        }
    }

    private static List<Udp4ModuleRecord> CreateUdp4ModuleRecordListFromIntPtr(IntPtr pointer, int num, int allocatedSize)
    {
        int singleSize = 160;

        List<Udp4ModuleRecord> records = new(num);

        byte[] managedArray = new byte[allocatedSize];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(managedArray, i + 0),
                    localPort: GetPortFromBytes(managedArray[(i + 4)..(i + 8)]),
                    pId: BitConverter.ToInt32(managedArray, i + 8),
                    createTimestamp: BitConverter.ToInt64(managedArray, i + 16),
                    specificPortBind: BitConverter.ToInt32(managedArray, i + 24),
                    flags: BitConverter.ToInt32(managedArray, i + 28),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(managedArray.AsSpan()[(i + 32)..(i + 160)]).ToArray()
                )
            );
        }
        return records;
    }

    #endregion

    #region GetBasicUdp4Connections()

    public static List<Udp4Record> GetBasicUdp4Connections(bool sortedOrder = true, UdpTableClass udpTable = UdpTableClass.UDP_TABLE_BASIC)
    {
        if (!(udpTable is UdpTableClass.UDP_TABLE_BASIC)) throw new ArgumentException("GetBasicUdp4Connections() supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)NetworkType.AF_INET, udpTable);

            HandleErrorCode(errorCode);

            return CreateUdp4BasicRecordListFromIntPtr((IntPtr)((long)_buffer + 4), GetCurrentEntriesNum());
        }
    }

    private static List<Udp4Record> CreateUdp4BasicRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 8;

        List<Udp4Record> records = new(num);

        byte[] managedArray = new byte[num * singleSize];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(managedArray, i + 0),
                    localPort: GetPortFromBytes(managedArray[(i + 4)..(i + 8)])
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    private static ushort GetPortFromBytes(byte[] bytes)
    {
        Array.Reverse(bytes);
        return BitConverter.ToUInt16(bytes, 2);
    }

    private static void HandleErrorCode(uint errorCode)
    {
        if (errorCode == (int)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) throw new OutOfMemoryException("Buffer is too small");
        if (errorCode != (int)ErrorReturnCodes.NO_ERROR) throw new ExternalException("iphlpapi.dll returned an error code: " + errorCode);
    }

    private static int GetCurrentEntriesNum()
    {
        byte[] dwNumEntriesBuffer = new byte[4];
        Marshal.Copy(_buffer, dwNumEntriesBuffer, 0, 4);
        return (int)BitConverter.ToUInt32(dwNumEntriesBuffer);
    }
}

public enum TcpTableClass
{
    TCP_TABLE_BASIC_LISTENER,
    TCP_TABLE_BASIC_CONNECTIONS,
    TCP_TABLE_BASIC_ALL,
    TCP_TABLE_OWNER_PID_LISTENER,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
    TCP_TABLE_OWNER_PID_ALL,
    TCP_TABLE_OWNER_MODULE_LISTENER,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
    TCP_TABLE_OWNER_MODULE_ALL
}

public enum UdpTableClass
{
    UDP_TABLE_BASIC,
    UDP_TABLE_OWNER_PID,
    UDP_TABLE_OWNER_MODULE
}

public enum MibState
{
    CLOSED = 1,
    LISTENING = 2,
    SYN_SENT = 3,
    SYN_RCVD = 4,
    ESTABLISHED = 5,
    FIN_WAIT1 = 6,
    FIN_WAIT2 = 7,
    CLOSE_WAIT = 8,
    CLOSING = 9,
    LAST_ACK = 10,
    TIME_WAIT = 11,
    DELETE_TCB = 12,
    NONE = 0
}

public enum ErrorReturnCodes
{
    NO_ERROR = 0,
    ERROR_INSUFFICIENT_BUFFER = 122,
    ERROR_INVALID_PARAMETER = 87,
}

public enum NetworkType
{
    AF_INET_UNSPEC = 0,
    AF_INET = 2, // IPV4
    AF_INET6 = 23, // IPV6
}

#region TCP Classes

public interface ITcpRecord
{

    public IPEndPoint LocalEndpoint { get; }

    public IPEndPoint RemoteEndpoint { get; }

}

#region TCP4 Classes

public class Tcp4Record : ITcpRecord
{

    public readonly uint LocalAddress;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint = null;

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalAddress, LocalPort);
            return _localEndpoint;
        }
    }

    public readonly uint RemoteAddress;

    public readonly ushort RemotePort;

    private IPEndPoint? _remoteEndpoint = null;

    public IPEndPoint RemoteEndpoint
    {
        get
        {
            _remoteEndpoint ??= new IPEndPoint(RemoteAddress, RemotePort);
            return _remoteEndpoint;
        }
    }

    public readonly MibState State;

    public Tcp4Record(MibState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort)
    {
        LocalAddress = localAddress;
        LocalPort = localPort;
        RemoteAddress = remoteAddress;
        RemotePort = remotePort;
        State = state;
    }

}

public class Tcp4ProcessRecord : Tcp4Record
{

    public readonly int ProcessId;

    public Tcp4ProcessRecord(MibState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int pId)
        : base(state, localAddress, localPort, remoteAddress, remotePort)
    {
        ProcessId = pId;
    }
}

public class Tcp4ModuleRecord : Tcp4ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime = null;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly ulong[] ModuleInfo;

    public Tcp4ModuleRecord(MibState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int pId, long createTimestamp, ulong[] moduleInfo)
        : base(state, localAddress, localPort, remoteAddress, remotePort, pId)
    {
        CreateTimestamp = createTimestamp;
        ModuleInfo = moduleInfo;
    }
}

#endregion

#endregion

#region UDP Classes

public interface IUdpRecord
{

    public IPEndPoint LocalEndpoint { get; }

}

#region UDP4 Classes

public class Udp4Record : IUdpRecord
{

    public readonly uint LocalAddress;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint = null;

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalAddress, LocalPort);
            return _localEndpoint;
        }
    }

    public Udp4Record(uint localAddress, ushort localPort)
    {
        LocalAddress = localAddress;
        LocalPort = localPort;
    }
}

public class Udp4ProcessRecord : Udp4Record
{

    private readonly int _processId;

    public int ProcessId { get { return _processId; } }

    public Udp4ProcessRecord(uint localAddress, ushort localPort, int pId)
        : base(localAddress, localPort)
    {
        _processId = pId;
    }
}

public class Udp4ModuleRecord : Udp4ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime = null;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly int SpecificPortBind;

    public readonly int Flags;

    public readonly ulong[] ModuleInfo;

    public Udp4ModuleRecord(uint localAddress, ushort localPort, int pId, long createTimestamp, int specificPortBind, int flags, ulong[] moduleInfo)
        : base(localAddress, localPort, pId)
    {
        CreateTimestamp = createTimestamp;
        SpecificPortBind = specificPortBind;
        Flags = flags;
        ModuleInfo = moduleInfo;
    }
}

#endregion

#endregion
