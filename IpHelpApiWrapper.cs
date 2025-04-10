using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

/**
 * Fast iphlpapi.dll wrapper for getting all tcp and udp connections
 * 
 * Only one call at a time, cant call from other threads if the wrapper is busy
 * 
 * By default the size of the Buffer to store the results of external calls is 64 kb
 **/
public sealed class IpHelpApiWrapper : IDisposable
{

    /**
     * PtrToStructure is BAD!
     **/

    public const string LibraryName = "iphlpapi.dll";

    [DllImport(LibraryName, CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    private int _bufferSize;

    public int BufferSize
    {
        get
        {
            return _bufferSize;
        }
        set
        {
            SetBufferSize(value);
        }
    }

    private IntPtr _buffer;

    private byte[] _bufferArray;

    private readonly object _bufferLockObject = new();

    private bool _disposed = false;

    public bool AutoResizeBuffer;

    public IpHelpApiWrapper(int bufferSize = 64 * 1024, bool autoResizeBuffer = true)
    {
        _bufferSize = bufferSize;
        _buffer = Marshal.AllocHGlobal(_bufferSize);
        _bufferArray = new byte[_bufferSize];
        AutoResizeBuffer = autoResizeBuffer;
    }

    public void SetBufferSize(int newSize)
    {
        lock (_bufferLockObject)
        {
            _buffer = Marshal.ReAllocHGlobal(_buffer, (IntPtr)newSize);
            Array.Resize(ref _bufferArray, newSize);
            _bufferSize = newSize;
        }
    }

    #region TCP Functions

    public IEnumerable<ITcpRecord> GetTcpTable(AddressFamily networkType, TcpTableClass tcpTable, bool sortedOrder = false)
    {
        return networkType switch
        {
            AddressFamily.InterNetwork => GetTcp4Connections(tcpTable, sortedOrder).Cast<ITcpRecord>(),
            AddressFamily.InterNetworkV6 => GetTcp6Connections(tcpTable, sortedOrder).Cast<ITcpRecord>(),
            _ => throw new ArgumentException("Invalid argument: networkType"),
        };
    }

    #region TCP4 Functions

    public IEnumerable<Tcp4Record> GetTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)
    {
        return tcpTable switch
        {
            TcpTableClass.BasicAll or TcpTableClass.BasicListeners or TcpTableClass.BasicConnections => GetBasicTcp4Connections(tcpTable, sortedOrder),
            TcpTableClass.ModuleAll or TcpTableClass.ModuleListeners or TcpTableClass.ModuleConnections => GetModuleTcp4Connections(tcpTable, sortedOrder).Cast<Tcp4Record>(),
            TcpTableClass.ProcessAll or TcpTableClass.ProcessListeners or TcpTableClass.ProcessConnections => GetProcessTcp4Connections(tcpTable, sortedOrder).Cast<Tcp4Record>(),
            _ => throw new ArgumentException("Invalid argument: tcpTable"),
        };
    }

    #region GetProcessTcp4Connections

    public List<Tcp4ProcessRecord> GetProcessTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp4Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4ProcessRecordListFromBuffer(bufferSize);
        }
    }

    private List<Tcp4ProcessRecord> CreateTcp4ProcessRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Tcp4ProcessRecord> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 20)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleTcp4Connections

    public List<Tcp4ModuleRecord> GetModuleTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp4Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4ModuleRecordListFromBuffer(bufferSize);
        }
    }

    private List<Tcp4ModuleRecord> CreateTcp4ModuleRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 160;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Tcp4ModuleRecord> records = new(num);
        for (int i = 8; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 20),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 24),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(32, 128)).ToArray()
                )
            );
        }

        return records;
    }

    #endregion

    #region GetBasicTcp4Connections

    public List<Tcp4Record> GetBasicTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.BasicAll or TcpTableClass.BasicConnections or TcpTableClass.BasicListeners)) throw new ArgumentException("GetBasicTcp4Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4BasicRecordListFromBuffer(bufferSize);
        }
    }

    private List<Tcp4Record> CreateTcp4BasicRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 20;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Tcp4Record> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17])
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    #region TCP6 Functions

    public IEnumerable<Tcp6Record> GetTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        return tcpTable switch
        {
            TcpTableClass.BasicAll or TcpTableClass.BasicListeners or TcpTableClass.BasicConnections => throw new InvalidOperationException("GetTcp6Connections doesnt support TcpTableClass.TCP_TABLE_BASIC_*"),
            TcpTableClass.ProcessAll or TcpTableClass.ProcessListeners or TcpTableClass.ProcessConnections => GetProcessTcp6Connections(tcpTable, sortedOrder).Cast<Tcp6Record>(),
            TcpTableClass.ModuleAll or TcpTableClass.ModuleListeners or TcpTableClass.ModuleConnections => GetModuleTcp6Connections(tcpTable, sortedOrder).Cast<Tcp6Record>(),
            _ => throw new ArgumentException("Invalid argument: tcpTable"),
        };
    }

    #region GetProcessTcp6Connections

    public List<Tcp6ProcessRecord> GetProcessTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp6Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp6ProcessRecordListFromBuffer(bufferSize);
        }
    }

    private List<Tcp6ProcessRecord> CreateTcp6ProcessRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 56;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Tcp6ProcessRecord> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    remoteAddress: _bufferArray[(i + 24)..(i + 40)],
                    remoteScopeId: BitConverter.ToUInt32(_bufferArray, i + 40),
                    remotePort: (ushort)((_bufferArray[i + 44] << 8) + _bufferArray[i + 45]),
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 48),
                    processId: BitConverter.ToInt32(_bufferArray, i + 52)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleTcp6Connections

    public List<Tcp6ModuleRecord> GetModuleTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp6Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp6ModuleRecordListFromBuffer(bufferSize);
        }
    }

    private List<Tcp6ModuleRecord> CreateTcp6ModuleRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 192;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Tcp6ModuleRecord> records = new(num);
        for (int i = 8; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    remoteAddress: _bufferArray[(i + 24)..(i + 40)],
                    remoteScopeId: BitConverter.ToUInt32(_bufferArray, i + 40),
                    remotePort: (ushort)((_bufferArray[i + 44] << 8) + _bufferArray[i + 45]),
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 48),
                    processId: BitConverter.ToInt32(_bufferArray, i + 52),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 56),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(64, 128)).ToArray()
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    #endregion

    #region UDP Functions

    public IEnumerable<IUdpRecord> GetUdpTable(AddressFamily networkType, UdpTableClass udpTable, bool sortedOrder = false)
    {
        return networkType switch
        {
            AddressFamily.InterNetwork => GetUdp4Connections(udpTable, sortedOrder).Cast<IUdpRecord>(),
            AddressFamily.InterNetworkV6 => GetUdp6Connections(udpTable, sortedOrder).Cast<IUdpRecord>(),
            _ => throw new ArgumentException("Invalid argument: networkType"),
        };
    }

    #region UDP4 Functions

    public IEnumerable<Udp4Record> GetUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        return udpTable switch
        {
            UdpTableClass.Basic => GetBasicUdp4Connections(udpTable, sortedOrder),
            UdpTableClass.Module => GetModuleUdp4Connections(udpTable, sortedOrder).Cast<Udp4Record>(),
            UdpTableClass.Process => GetProcessUdp4Connections(udpTable, sortedOrder).Cast<Udp4Record>(),
            _ => throw new ArgumentException("Invalid argument: udpTable"),
        };
    }

    #region GetProcessUdp4Connections

    public List<Udp4ProcessRecord> GetProcessUdp4Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp4Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4ProcessRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp4ProcessRecord> CreateUdp4ProcessRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 12;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp4ProcessRecord> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 8)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleUdp4Connections

    public List<Udp4ModuleRecord> GetModuleUdp4Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp4Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4ModuleRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp4ModuleRecord> CreateUdp4ModuleRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 160;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp4ModuleRecord> records = new(num);
        for (int i = 8; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 8),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 16),
                    specificPortBind: _bufferArray[i + 24] == 1,
                    flags: BitConverter.ToInt32(_bufferArray, i + 28),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(32, 128)).ToArray()
                )
            );
        }
        return records;
    }

    #endregion

    #region GetBasicUdp4Connections

    public List<Udp4Record> GetBasicUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp4Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4BasicRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp4Record> CreateUdp4BasicRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 8;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp4Record> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5])
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    #region UDP6 Functions

    public IEnumerable<Udp6Record> GetUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        return udpTable switch
        {
            UdpTableClass.Basic => GetBasicUdp6Connections(udpTable, sortedOrder),
            UdpTableClass.Module => GetModuleUdp6Connections(udpTable, sortedOrder).Cast<Udp6Record>(),
            UdpTableClass.Process => GetProcessUdp6Connections(udpTable, sortedOrder).Cast<Udp6Record>(),
            _ => throw new ArgumentException("Invalid argument: udpTable"),
        };
    }

    #region GetProcessUdp6Connections

    public List<Udp6ProcessRecord> GetProcessUdp6Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp6Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6ProcessRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp6ProcessRecord> CreateUdp6ProcessRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 28;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp6ProcessRecord> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 24)
                )
            );
        }
        return records;
    }

    #endregion

    #region GetModuleUdp6Connections

    public List<Udp6ModuleRecord> GetModuleUdp6Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp6Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6ModuleRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp6ModuleRecord> CreateUdp6ModuleRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 176;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp6ModuleRecord> records = new(num);
        for (int i = 8; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 24),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 32),
                    specificPortBind: _bufferArray[i + 40] == 1,
                    flags: BitConverter.ToInt32(_bufferArray, i + 44),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(48, 128)).ToArray()
                )
            );
        }
        return records;
    }

    #endregion

    #region GetBasicUdp6Connections

    public List<Udp6Record> GetBasicUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp6Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            uint errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_buffer, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6BasicRecordListFromBuffer(bufferSize);
        }
    }

    private List<Udp6Record> CreateUdp6BasicRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<Udp6Record> records = new(num);
        for (int i = 4; i < (allocatedSize - singleSize); i += singleSize)
        {
            records.Add(new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21])
                )
            );
        }
        return records;
    }

    #endregion

    #endregion

    #endregion

    #region GetIpNetTableRecords()

    public List<PhysicalAddressRecord> GetIpNetTableRecords(bool sortedOrder = false)
    {
        ThrowIfDisposed();

        int bufferSize = BufferSize;

        lock (_bufferLockObject)
        {
            int errorCode = GetIpNetTable(_buffer, ref bufferSize, sortedOrder);

            while (AutoResizeBuffer && (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER))
            {
                SetBufferSize(bufferSize);
                errorCode = GetIpNetTable(_buffer, ref bufferSize, sortedOrder);
            }

            HandleErrorCode((uint)errorCode);
            if (errorCode == (int)ErrorReturnCodes.ERROR_NO_DATA) return new();

            return CreatePhysicalAddressRecordListFromBuffer(bufferSize);
        }
    }

    private List<PhysicalAddressRecord> CreatePhysicalAddressRecordListFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        Marshal.Copy(_buffer, _bufferArray, 0, allocatedSize);
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        List<PhysicalAddressRecord> records = new(num);
        allocatedSize = 4 + (singleSize * num);
        for (int i = 4; i < allocatedSize; i += singleSize)
        {
            records.Add(new
                (
                    physicalAddress: _bufferArray[(i + 8)..(i + 14)],
                    ipAddress: BitConverter.ToUInt32(_bufferArray, i + 16),
                    netType: (IpNetType)BitConverter.ToUInt32(_bufferArray, i + 20)
                )
            );
        }
        return records;
    }

    #endregion

    private static void HandleErrorCode(uint errorCode)
    {
        if (errorCode == (int)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) throw new OutOfMemoryException("Buffer is too small");
        if (errorCode != (int)ErrorReturnCodes.NO_ERROR && (errorCode != (int)ErrorReturnCodes.ERROR_NO_DATA)) throw new Win32Exception((int)errorCode);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(GetType().FullName);
    }

    public void Dispose()
    {
        if (_disposed) return;
        Marshal.FreeHGlobal(_buffer);
        GC.SuppressFinalize(this);
        _disposed = true;
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

#region TCP Classes

public interface ITcpRecord
{

    public IPAddress LocalIPAddress { get; }

    public IPEndPoint LocalEndpoint { get; }

    public IPAddress RemoteIPAddress { get; }

    public IPEndPoint RemoteEndpoint { get; }

}

#region TCP4 Classes

public class Tcp4Record : ITcpRecord
{

    public readonly uint LocalAddress;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint;

    private IPAddress? _localIPAddress;

    public IPAddress LocalIPAddress
    {
        get
        {
            _localIPAddress ??= new IPAddress(LocalAddress);
            return _localIPAddress;
        }
    }

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalIPAddress, LocalPort);
            return _localEndpoint;
        }
    }

    public readonly uint RemoteAddress;

    public readonly ushort RemotePort;

    private IPEndPoint? _remoteEndpoint;

    private IPAddress? _remoteIPAddress;

    public IPAddress RemoteIPAddress
    {
        get
        {
            _remoteIPAddress ??= new IPAddress(RemoteAddress);
            return _remoteIPAddress;
        }
    }

    public IPEndPoint RemoteEndpoint
    {
        get
        {
            _remoteEndpoint ??= new IPEndPoint(RemoteIPAddress, RemotePort);
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

    public Tcp4ProcessRecord(MibState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int processId)
        : base(state, localAddress, localPort, remoteAddress, remotePort)
    {
        ProcessId = processId;
    }
}

public class Tcp4ModuleRecord : Tcp4ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly ulong[] ModuleInfo;

    public Tcp4ModuleRecord(MibState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int processId, long createTimestamp, ulong[] moduleInfo)
        : base(state, localAddress, localPort, remoteAddress, remotePort, processId)
    {
        CreateTimestamp = createTimestamp;
        ModuleInfo = moduleInfo;
    }
}

#endregion

#region TCP6 Classes

public class Tcp6Record : ITcpRecord
{

    public readonly byte[] LocalAddress;

    public readonly uint LocalScopeId;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint;

    private IPAddress? _localIPAddress;

    public IPAddress LocalIPAddress
    {
        get
        {
            _localIPAddress ??= new IPAddress(LocalAddress, LocalScopeId);
            return _localIPAddress;
        }
    }

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalIPAddress, LocalPort);
            return _localEndpoint;
        }
    }

    public readonly byte[] RemoteAddress;

    public readonly uint RemoteScopeId;

    public readonly ushort RemotePort;

    private IPEndPoint? _remoteEndpoint;

    private IPAddress? _remoteIPAddress;

    public IPAddress RemoteIPAddress
    {
        get
        {
            _remoteIPAddress ??= new IPAddress(RemoteAddress, RemoteScopeId);
            return _remoteIPAddress;
        }
    }

    public IPEndPoint RemoteEndpoint
    {
        get
        {
            _remoteEndpoint ??= new IPEndPoint(RemoteIPAddress, RemotePort);
            return _remoteEndpoint;
        }
    }

    public readonly MibState State;

    public Tcp6Record(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, MibState state)
    {
        LocalAddress = localAddress;
        LocalScopeId = localScopeId;
        LocalPort = localPort;
        RemoteAddress = remoteAddress;
        RemoteScopeId = remoteScopeId;
        RemotePort = remotePort;
        State = state;
    }
}

public class Tcp6ProcessRecord : Tcp6Record
{

    public readonly int ProcessId;

    public Tcp6ProcessRecord(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, MibState state, int processId)
        : base(localAddress, localScopeId, localPort, remoteAddress, remoteScopeId, remotePort, state)
    {
        ProcessId = processId;
    }

}

public class Tcp6ModuleRecord : Tcp6ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly ulong[] ModuleInfo;

    public Tcp6ModuleRecord(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, MibState state, int processId, long createTimestamp, ulong[] moduleInfo)
        : base(localAddress, localScopeId, localPort, remoteAddress, remoteScopeId, remotePort, state, processId)
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

    public IPAddress LocalIPAddress { get; }

    public IPEndPoint LocalEndpoint { get; }

}

#region UDP4 Classes

public class Udp4Record : IUdpRecord
{

    public readonly uint LocalAddress;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint;

    private IPAddress? _localIPAddress;

    public IPAddress LocalIPAddress
    {
        get
        {
            _localIPAddress ??= new IPAddress(LocalAddress);
            return _localIPAddress;
        }
    }

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalIPAddress, LocalPort);
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

    public readonly int ProcessId;

    public Udp4ProcessRecord(uint localAddress, ushort localPort, int processId)
        : base(localAddress, localPort)
    {
        ProcessId = processId;
    }
}

public class Udp4ModuleRecord : Udp4ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly bool SpecificPortBind;

    public readonly int Flags;

    public readonly ulong[] ModuleInfo;

    public Udp4ModuleRecord(uint localAddress, ushort localPort, int processId, long createTimestamp, bool specificPortBind, int flags, ulong[] moduleInfo)
        : base(localAddress, localPort, processId)
    {
        CreateTimestamp = createTimestamp;
        SpecificPortBind = specificPortBind;
        Flags = flags;
        ModuleInfo = moduleInfo;
    }
}

#endregion

#region UDP6 Classes

public class Udp6Record : IUdpRecord
{

    public readonly byte[] LocalAddress;

    public readonly uint LocalScopeId;

    public readonly ushort LocalPort;

    private IPEndPoint? _localEndpoint;

    private IPAddress? _localIPAddress;

    public IPAddress LocalIPAddress
    {
        get
        {
            _localIPAddress ??= new IPAddress(LocalAddress, LocalScopeId);
            return _localIPAddress;
        }
    }

    public IPEndPoint LocalEndpoint
    {
        get
        {
            _localEndpoint ??= new IPEndPoint(LocalIPAddress, LocalPort);
            return _localEndpoint;
        }
    }

    public Udp6Record(byte[] localAddress, uint localScopeId, ushort localPort)
    {
        LocalAddress = localAddress;
        LocalScopeId = localScopeId;
        LocalPort = localPort;
    }
}

public class Udp6ProcessRecord : Udp6Record
{

    public readonly int ProcessId;

    public Udp6ProcessRecord(byte[] localAddress, uint localScopeId, ushort localPort, int processId)
        : base(localAddress, localScopeId, localPort)

    {
        ProcessId = processId;
    }
}

public class Udp6ModuleRecord : Udp6ProcessRecord
{

    public readonly long CreateTimestamp;

    private DateTime? _createDateTime;

    public DateTime CreateDateTime
    {
        get
        {
            _createDateTime ??= DateTime.FromFileTime(CreateTimestamp);
            return (DateTime)_createDateTime;
        }
    }

    public readonly bool SpecificPortBind;

    public readonly int Flags;

    public readonly ulong[] ModuleInfo;

    public Udp6ModuleRecord(byte[] localAddress, uint localScopeId, ushort localPort, int processId, long createTimestamp, bool specificPortBind, int flags, ulong[] moduleInfo)
        : base(localAddress, localScopeId, localPort, processId)
    {
        CreateTimestamp = createTimestamp;
        SpecificPortBind = specificPortBind;
        Flags = flags;
        ModuleInfo = moduleInfo;
    }
}

#endregion

#endregion

public class PhysicalAddressRecord
{

    public readonly uint IpAddressInt;

    private IPAddress? _ipAddress;

    public IPAddress IpAddress
    {
        get
        {
            _ipAddress ??= new(IpAddressInt);
            return _ipAddress;
        }
    }

    public readonly byte[] PhysicalAddressBytes;

    private PhysicalAddress? _physicalAddress;

    public PhysicalAddress PhysicalAddress
    {
        get
        {
            _physicalAddress ??= new(PhysicalAddressBytes);
            return _physicalAddress;
        }
    }

    public readonly IpNetType NetType;

    public PhysicalAddressRecord(uint ipAddress, byte[] physicalAddress, IpNetType netType)
    {
        IpAddressInt = ipAddress;
        PhysicalAddressBytes = physicalAddress;
        NetType = netType;
    }
}