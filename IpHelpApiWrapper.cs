using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;


/**
 * Fast iphlpapi.dll wrapper for getting all tcp and udp connections
 * 
 * Only one call at a time, cant call from other threads if the wrapper is busy
 **/
public sealed class IpHelpApiWrapper : IDisposable
{

    /**
     * PtrToStructure is bad for performance;
     * 
     * This code uses an internal buffer to store results of calls to iphlpapi, iphlpapi writes directly to this buffer
     * 
     * No unsafe code
     **/

    public const string LibraryName = "iphlpapi.dll";

    #region Native functions

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetBestInterface(uint dwDestAddr, ref uint pdwBestIfIndex);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetBestInterfaceEx(IntPtr dwDestAddr, ref uint pdwBestIfIndex);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

    #endregion

    /// <summary>
    /// Gets or sets the size of the internal buffer to store results
    /// When UseSharedArrayPool is true, BufferSize is not always equals to the one set, but it's always >= to the one set
    /// </summary>
    public int BufferSize
    {
        get
        {
            return _bufferArray.Length;
        }
        set
        {
            SetBufferSize(value);
        }
    }

    private IntPtr _bufferPtr;

    private byte[] _bufferArray;

    private GCHandle _bufferGCHandle;

    public bool Disposed { get; private set; } = false;

    /// <summary>
    /// Gets or sets the flag indicating whenever the buffer should be auto resized if it's not enough to store the results of the external call
    /// </summary>
    public bool AutoResizeBuffer;

    /// <summary>
    /// Gets the Array pool used by the wrapper; if UsedArrayPool is null, no array pool is used
    /// </summary>
    public readonly ArrayPool<byte>? UsedArrayPool = null;

    /// <summary>
    /// Shared instance of the wrapper. Uses shared array pool as buffer
    /// DO NOT DISPOSE
    /// </summary>
    public static readonly IpHelpApiWrapper Shared = new(arrayPool: ArrayPool<byte>.Shared);

    /// <summary>
    /// Creates new IpHelpApiWrapper
    /// </summary>
    /// <param name="bufferSize">Size of internal buffer for storing results of external calls</param>
    /// <param name="autoResizeBuffer">If set to true, internal buffer would be auto resized when it's not big enough</param>
    /// <param name="arrayPool">Array pool to get internal byte array buffers; if set to null, allocates new byte array for internal buffer</param>
    public IpHelpApiWrapper(int bufferSize = 16 * 1024, bool autoResizeBuffer = true, ArrayPool<byte>? arrayPool = null)
    {
        UsedArrayPool = arrayPool;
        _bufferArray = (UsedArrayPool != null) ? UsedArrayPool.Rent(bufferSize) : new byte[bufferSize];
        _bufferGCHandle = GCHandle.Alloc(_bufferArray, GCHandleType.Pinned);
        _bufferPtr = _bufferGCHandle.AddrOfPinnedObject();
        AutoResizeBuffer = autoResizeBuffer;
    }

    /// <summary>
    /// Changes size of internal buffer
    /// </summary>
    /// <param name="newSize">New buffer size</param>
    public void SetBufferSize(int newSize)
    {
        ThrowIfDisposed();
        lock (_bufferArray)
        {
            _bufferGCHandle.Free();

            if (UsedArrayPool != null)
            {
                UsedArrayPool.Return(_bufferArray, true);
                _bufferArray = UsedArrayPool.Rent(newSize);
            }
            else
            {
                Array.Resize(ref _bufferArray, newSize);
            }
            _bufferGCHandle = GCHandle.Alloc(_bufferArray, GCHandleType.Pinned);
            _bufferPtr = _bufferGCHandle.AddrOfPinnedObject();
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

    public Tcp4ProcessRecord[] GetProcessTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp4Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4ProcessRecordArrayFromBuffer(bufferSize);
        }
    }

    private Tcp4ProcessRecord[] CreateTcp4ProcessRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Tcp4ProcessRecord[] records = new Tcp4ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 20)
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetModuleTcp4Connections

    public Tcp4ModuleRecord[] GetModuleTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp4Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4ModuleRecordArrayFromBuffer(bufferSize);
        }
    }

    private Tcp4ModuleRecord[] CreateTcp4ModuleRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 160;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Tcp4ModuleRecord[] records = new Tcp4ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++)
        {
            records[k] = new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 20),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 24),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(32, 128)).ToArray()
                );
            i += singleSize;
        }

        return records;
    }

    #endregion

    #region GetBasicTcp4Connections

    public Tcp4Record[] GetBasicTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.BasicAll or TcpTableClass.BasicConnections or TcpTableClass.BasicListeners)) throw new ArgumentException("GetBasicTcp4Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp4BasicRecordArrayFromBuffer(bufferSize);
        }
    }

    private Tcp4Record[] CreateTcp4BasicRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 20;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Tcp4Record[] records = new Tcp4Record[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 0),
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 4),
                    localPort: (ushort)((_bufferArray[i + 8] << 8) + _bufferArray[i + 9]),
                    remoteAddress: BitConverter.ToUInt32(_bufferArray, i + 12),
                    remotePort: (ushort)((_bufferArray[i + 16] << 8) + _bufferArray[i + 17])
                );
            i += singleSize;
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

    public Tcp6ProcessRecord[] GetProcessTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp6Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp6ProcessRecordArrayFromBuffer(bufferSize);
        }
    }

    private Tcp6ProcessRecord[] CreateTcp6ProcessRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 56;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Tcp6ProcessRecord[] records = new Tcp6ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    remoteAddress: _bufferArray[(i + 24)..(i + 40)],
                    remoteScopeId: BitConverter.ToUInt32(_bufferArray, i + 40),
                    remotePort: (ushort)((_bufferArray[i + 44] << 8) + _bufferArray[i + 45]),
                    state: (ConnectionState)BitConverter.ToUInt32(_bufferArray, i + 48),
                    processId: BitConverter.ToInt32(_bufferArray, i + 52)
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetModuleTcp6Connections

    public Tcp6ModuleRecord[] GetModuleTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp6Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);
            }

            HandleErrorCode(errorCode);

            return CreateTcp6ModuleRecordArrayFromBuffer(bufferSize);
        }
    }

    private Tcp6ModuleRecord[] CreateTcp6ModuleRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 192;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Tcp6ModuleRecord[] records = new Tcp6ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++)
        {
            records[k] = new
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
                );
            i += singleSize;
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

    public Udp4ProcessRecord[] GetProcessUdp4Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp4Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4ProcessRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp4ProcessRecord[] CreateUdp4ProcessRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 12;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp4ProcessRecord[] records = new Udp4ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 8)
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetModuleUdp4Connections

    public Udp4ModuleRecord[] GetModuleUdp4Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp4Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4ModuleRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp4ModuleRecord[] CreateUdp4ModuleRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 160;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp4ModuleRecord[] records = new Udp4ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 8),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 16),
                    specificPortBind: _bufferArray[i + 24] == 1,
                    flags: BitConverter.ToInt32(_bufferArray, i + 28),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(32, 128)).ToArray()
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetBasicUdp4Connections

    public Udp4Record[] GetBasicUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp4Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp4BasicRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp4Record[] CreateUdp4BasicRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 8;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp4Record[] records = new Udp4Record[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: BitConverter.ToUInt32(_bufferArray, i + 0),
                    localPort: (ushort)((_bufferArray[i + 4] << 8) + _bufferArray[i + 5])
                );
            i += singleSize;
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

    public Udp6ProcessRecord[] GetProcessUdp6Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp6Connections supports only processes");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6ProcessRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp6ProcessRecord[] CreateUdp6ProcessRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 28;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp6ProcessRecord[] records = new Udp6ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 24)
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetModuleUdp6Connections

    public Udp6ModuleRecord[] GetModuleUdp6Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp6Connections supports only modules");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6ModuleRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp6ModuleRecord[] CreateUdp6ModuleRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 176;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp6ModuleRecord[] records = new Udp6ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21]),
                    processId: BitConverter.ToInt32(_bufferArray, i + 24),
                    createTimestamp: BitConverter.ToInt64(_bufferArray, i + 32),
                    specificPortBind: _bufferArray[i + 40] == 1,
                    flags: BitConverter.ToInt32(_bufferArray, i + 44),
                    moduleInfo: MemoryMarshal.Cast<byte, ulong>(_bufferArray.AsSpan(48, 128)).ToArray()
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetBasicUdp6Connections

    public Udp6Record[] GetBasicUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp6Connections supports only basic");

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);
            }

            HandleErrorCode(errorCode);

            return CreateUdp6BasicRecordArrayFromBuffer(bufferSize);
        }
    }

    private Udp6Record[] CreateUdp6BasicRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        Udp6Record[] records = new Udp6Record[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    localAddress: _bufferArray[(i + 0)..(i + 16)],
                    localScopeId: BitConverter.ToUInt32(_bufferArray, i + 16),
                    localPort: (ushort)((_bufferArray[i + 20] << 8) + _bufferArray[i + 21])
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #endregion

    #endregion

    #region GetIpNetTableRecords()

    public PhysicalAddressRecord[] GetIpNetTableRecords(bool sortedOrder = false)
    {
        ThrowIfDisposed();

        int bufferSize = BufferSize;

        lock (_bufferArray)
        {
            uint errorCode = GetIpNetTable(_bufferPtr, ref bufferSize, sortedOrder);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                SetBufferSize(bufferSize);
                errorCode = GetIpNetTable(_bufferPtr, ref bufferSize, sortedOrder);
            }

            HandleErrorCode(errorCode);
            if (errorCode == (uint)ErrorReturnCodes.ERROR_NO_DATA) return Array.Empty<PhysicalAddressRecord>();

            return CreatePhysicalAddressRecordArrayFromBuffer(bufferSize);
        }
    }

    private PhysicalAddressRecord[] CreatePhysicalAddressRecordArrayFromBuffer(int allocatedSize)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(_bufferArray);
        PhysicalAddressRecord[] records = new PhysicalAddressRecord[num];
        for (int k = 0, i = 4; k < num; k++)
        {
            records[k] = new
                (
                    physicalAddress: _bufferArray[(i + 8)..(i + 14)],
                    ipAddress: BitConverter.ToUInt32(_bufferArray, i + 16),
                    netType: (IpNetType)BitConverter.ToUInt32(_bufferArray, i + 20)
                );
            i += singleSize;
        }
        return records;
    }

    #endregion

    #region GetBestInterfaceIndex()

    public static uint GetBestInterfaceIndex(uint address)
    {
        uint index = 0;
        uint errorCode = GetBestInterface(address, ref index);
        HandleErrorCode(errorCode);
        return index;
    }

    public static uint GetBestInterfaceIndex(IPAddress address)
    {
        return GetBestInterfaceIndex(GetIPV4AddressUint(address));
    }

    #endregion

    #region GetBestInterface4()

    public static NetworkInterface GetBestInterface4(IPAddress address, NetworkInterface[]? interfaces = null)
    {
        // Use GetBestInterfaceIndex instead of GetBestInterfaceEx because it's faster (BARELY!) and doesnt allocate memory on the heap
        uint bestIndex = GetBestInterfaceIndex(address);
        interfaces ??= NetworkInterface.GetAllNetworkInterfaces();
        foreach (NetworkInterface netInterface in interfaces)
        {
            if (netInterface.GetIPProperties().GetIPv4Properties().Index == bestIndex) return netInterface;
        }
        throw new InvalidOperationException("Unable to find the best interface");
    }

    #endregion

    #region GetBestInterfaceIndexEx()

    public static uint GetBestInterfaceIndexEx(IPAddress address)
    {
        byte[] socksaddr_in6 = new byte[26];
        Span<byte> byteSpan = new(socksaddr_in6);

        socksaddr_in6[0] = (byte)(((short)address.AddressFamily) & 255);
        socksaddr_in6[1] = (byte)(((short)address.AddressFamily) >> 8);

        if (!address.TryWriteBytes(byteSpan[2..], out int _)) throw new InvalidDataException("Unable to get ip address bytes");

        GCHandle handle = GCHandle.Alloc(socksaddr_in6, GCHandleType.Pinned);
        IntPtr ptr = handle.AddrOfPinnedObject();

        uint index = 0;
        uint errorCode = GetBestInterfaceEx(ptr, ref index);
        handle.Free();
        HandleErrorCode(errorCode);
        return index;
    }

    #endregion

    #region GetBestInterface6()

    public static NetworkInterface GetBestInterface6(IPAddress address, NetworkInterface[]? interfaces = null)
    {
        uint bestIndex = GetBestInterfaceIndexEx(address);
        interfaces ??= NetworkInterface.GetAllNetworkInterfaces();
        foreach (NetworkInterface netInterface in interfaces)
        {
            if (netInterface.GetIPProperties().GetIPv6Properties().Index == bestIndex) return netInterface;
        }
        throw new InvalidOperationException("Unable to find the best interface");
    }

    #endregion

    #region GetBestInterface()

    public static NetworkInterface GetBestInterface(IPAddress address, NetworkInterface[]? interfaces = null)
    {
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => GetBestInterface4(address, interfaces),
            AddressFamily.InterNetworkV6 => GetBestInterface6(address, interfaces),
            _ => throw new ArgumentException("AddressFamily should be InterNetwork or InterNetworkV6"),
        };
    }

    #endregion

    #region SendARP()

    public static byte[] SendARP(uint destionationAddress, uint sourceAddress = 0)
    {
        byte[] physicalAddress = new byte[6];
        int addressLength = physicalAddress.Length;
        uint errorCode = SendARP(destionationAddress, sourceAddress, physicalAddress, ref addressLength);
        while (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) // Should we resize tho?
        {
            Array.Resize(ref physicalAddress, addressLength);
            // Do not resize addressLength!!! This gets overriden when we call SendARP native
            errorCode = SendARP(destionationAddress, sourceAddress, physicalAddress, ref addressLength);
        }
        HandleErrorCode(errorCode);
        return physicalAddress;
    }

    /// <summary>
    /// Send Address Resolution Protocol (ARP) packet to resolve the physical address of the device with the desired ipv4 address in the local network.
    /// If the ARP entry exists in the ARP table on the local device, returns the target address, otherwise sends resolution packet
    /// </summary>
    /// <param name="destAddress">Ip address to be resolved</param>
    /// <param name="srcAddress">Network interface ip address, if set to null, would automatically resolve from the main interface</param>
    /// <returns>Resolved physical address</returns>
    public static PhysicalAddress SendARP(IPAddress destAddress, IPAddress? srcAddress = null)
    {
        return new PhysicalAddress(SendARP(GetIPV4AddressUint(destAddress), srcAddress == null ? 0 : GetIPV4AddressUint(srcAddress)));
    }

    #endregion

    /// <summary>
    /// Returns ipv4 address in uint format
    /// </summary>
    /// <param name="ipAddr">Address to convert</param>
    /// <returns>Address in uint format</returns>
    /// <exception cref="InvalidOperationException">Provided ip address is not ipv4</exception>
    /// <exception cref="InvalidDataException">Unable to write ip address bytes</exception>
    public static uint GetIPV4AddressUint(IPAddress ipAddr)
    {
        if (ipAddr.AddressFamily is not AddressFamily.InterNetwork) throw new InvalidOperationException("GetIPV4Adress supports only ipv4 addresses");
        Span<byte> addrBytes = stackalloc byte[4];
        if (!ipAddr.TryWriteBytes(addrBytes, out int _)) throw new InvalidDataException("Unable to get ip address bytes");
        return ((uint)addrBytes[3] << 24) + ((uint)addrBytes[2] << 16) + ((uint)addrBytes[1] << 8) + addrBytes[0];
    }

    private static void HandleErrorCode(uint errorCode)
    {
        if (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) throw new OutOfMemoryException("Buffer is too small");
        if ((errorCode != (uint)ErrorReturnCodes.NO_ERROR) && (errorCode != (int)ErrorReturnCodes.ERROR_NO_DATA)) throw new Win32Exception((int)errorCode);
    }

    private void ThrowIfDisposed()
    {
        if (Disposed) throw new ObjectDisposedException(GetType().FullName);
    }

    public void Dispose()
    {
        ThrowIfDisposed();
        _bufferGCHandle.Free();
        if (UsedArrayPool != null)
        {
            UsedArrayPool.Return(_bufferArray);
        }
        GC.SuppressFinalize(this);
        Disposed = true;
    }
}

public enum IpNetType
{
    Other = 1,
    Invalid = 2,
    Dynamic = 3,
    Static = 4,
}

public enum TcpTableClass
{
    BasicListeners,
    BasicConnections,
    BasicAll,
    ProcessListeners,
    ProcessConnections,
    ProcessAll,
    ModuleListeners,
    ModuleConnections,
    ModuleAll
}

public enum UdpTableClass
{
    Basic,
    Process,
    Module
}

public enum ConnectionState
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

public enum ErrorReturnCodes : uint
{
    NO_ERROR = 0,
    ERROR_INSUFFICIENT_BUFFER = 122,
    ERROR_INVALID_PARAMETER = 87,
    ERROR_NO_DATA = 238,
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

    public readonly ConnectionState State;

    public Tcp4Record(ConnectionState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort)
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

    public Tcp4ProcessRecord(ConnectionState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int processId)
        : base(state, localAddress, localPort, remoteAddress, remotePort)
    {
        ProcessId = processId;
    }
}

public sealed class Tcp4ModuleRecord : Tcp4ProcessRecord
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

    public Tcp4ModuleRecord(ConnectionState state, uint localAddress, ushort localPort, uint remoteAddress, ushort remotePort, int processId, long createTimestamp, ulong[] moduleInfo)
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

    public readonly ConnectionState State;

    public Tcp6Record(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, ConnectionState state)
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

    public Tcp6ProcessRecord(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, ConnectionState state, int processId)
        : base(localAddress, localScopeId, localPort, remoteAddress, remoteScopeId, remotePort, state)
    {
        ProcessId = processId;
    }

}

public sealed class Tcp6ModuleRecord : Tcp6ProcessRecord
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

    public Tcp6ModuleRecord(byte[] localAddress, uint localScopeId, ushort localPort, byte[] remoteAddress, uint remoteScopeId, ushort remotePort, ConnectionState state, int processId, long createTimestamp, ulong[] moduleInfo)
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

public sealed class Udp4ModuleRecord : Udp4ProcessRecord
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

public sealed class Udp6ModuleRecord : Udp6ProcessRecord
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

public sealed class PhysicalAddressRecord
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