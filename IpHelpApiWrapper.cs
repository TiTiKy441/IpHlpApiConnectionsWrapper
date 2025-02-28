using System.Net;
using System.Runtime.InteropServices;

/**
* Fast iphlpapi.dll wrapper for getting all tcp and udp connections
* 
* Only one call at a time, cant call from other threads if the wrapper is busy
* 
* By default the size of the Buffer to store the results of external calls is 1 mb
**/
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

    public static List<TcpProcessRecord> GetAllTcpConnections(NetworkType network = NetworkType.AF_INET)
    {
        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, true, (int)network, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

            if (errorCode == (int)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) throw new OutOfMemoryException("Buffer is too small");
            if (errorCode != (int)ErrorReturnCodes.NO_ERROR) throw new ExternalException("iphlpapi.dll returned an error code: " + errorCode);

            // Copy 4 bytes to see the amount of records
            byte[] dwNumEntriesBuffer = new byte[4];
            Marshal.Copy(_buffer, dwNumEntriesBuffer, 0, 4);
            uint entiresNum = BitConverter.ToUInt32(dwNumEntriesBuffer);

            return CreateTcpProcessRecordListFromIntPtr((IntPtr)((long)_buffer + 4), (int)entiresNum);
        }
    }

    private static List<TcpProcessRecord> CreateTcpProcessRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 24;//Marshal.SizeOf(typeof(TcpProcessRecord))

        List<TcpProcessRecord> records = new(num);

        byte[] managedArray = new byte[singleSize * num];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    localEndpoint: new IPEndPoint(BitConverter.ToUInt32(managedArray, i + 4), GetPortFromBytes(managedArray[(i + 8)..(i + 12)])),
                    remoteEndpoint: new IPEndPoint(BitConverter.ToUInt32(managedArray, i + 12), GetPortFromBytes(managedArray[(i + 16)..(i + 20)])),
                    pId: BitConverter.ToInt32(managedArray, i + 20),
                    state: (MibTcpState)BitConverter.ToUInt32(managedArray, i + 0)
                )
            );
        }
        return records;
    }

    public static List<UdpProcessRecord> GetAllUdpConnections(NetworkType network = NetworkType.AF_INET)
    {
        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, true, (int)network, UdpTableClass.UDP_TABLE_OWNER_PID);

            if (errorCode == (int)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) throw new OutOfMemoryException("Buffer is too small");
            if (errorCode != (int)ErrorReturnCodes.NO_ERROR) throw new ExternalException("iphlpapi.dll returned an error code: " + errorCode);

            // Copy 4 bytes to see the amount of records
            byte[] dwNumEntriesBuffer = new byte[4];
            Marshal.Copy(_buffer, dwNumEntriesBuffer, 0, 4);
            uint entiresNum = BitConverter.ToUInt32(dwNumEntriesBuffer);

            return CreateUdpProcessRecordListFromIntPtr((IntPtr)((long)_buffer + 4), (int)entiresNum);
        }
    }

    private static List<UdpProcessRecord> CreateUdpProcessRecordListFromIntPtr(IntPtr pointer, int num)
    {
        int singleSize = 12;//Marshal.SizeOf(typeof(UdpProcessRecord));

        List<UdpProcessRecord> records = new(num);

        byte[] managedArray = new byte[singleSize * num];
        Marshal.Copy(pointer, managedArray, 0, singleSize * num);
        for (int i = 0; i < num * singleSize; i += singleSize)
        {
            records.Add(new
                (
                    localEndpoint: new IPEndPoint(BitConverter.ToUInt32(managedArray, i + 0), GetPortFromBytes(managedArray[(i + 4)..(i + 8)])),
                    pId: BitConverter.ToInt32(managedArray, i + 8)
                )
            );
        }
        return records;
    }

    private static ushort GetPortFromBytes(byte[] bytes)
    {
        return BitConverter.ToUInt16(new byte[2] { bytes[1], bytes[0] }, 0);
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

public enum MibTcpState
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

public readonly struct TcpProcessRecord
{

    public readonly IPEndPoint LocalEndpoint;

    public readonly IPEndPoint RemoteEndpoint;

    public readonly MibTcpState State;

    public readonly int ProcessId;

    public TcpProcessRecord(IPEndPoint localEndpoint, IPEndPoint remoteEndpoint, int pId, MibTcpState state)
    {
        LocalEndpoint = localEndpoint;
        RemoteEndpoint = remoteEndpoint;
        ProcessId = pId;
        State = state;
    }
}

public readonly struct UdpProcessRecord
{
    public readonly IPEndPoint LocalEndpoint;

    public readonly int ProcessId;

    public UdpProcessRecord(IPEndPoint localEndpoint, int pId)
    {
        LocalEndpoint = localEndpoint;
        ProcessId = pId;
    }
}
