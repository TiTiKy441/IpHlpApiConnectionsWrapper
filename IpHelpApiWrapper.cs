using System.Buffers;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;


/**
 * Speed-oriented iphlpapi.dll wrapper
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
     * 
     * We use GetPinnableReference() for static functions which we are not supposed to,
     * so if it dissapers, static functions WILL BE removed
     **/

    /**
     * Consider the following before using static functions from this class:
     * 
     * Static functions use stack allocated memory instead of heap allocated memory that is used by instance functions
     * Static functions from this class sometimes are faster than their instance functions, but this comes at a cost
     * We dont know in advance how big should our buffer be so we set the buffer size to a fixed value while calling the function (bufferSize)
     * So if the buffer is not big enough, an exception will be thrown and there is no option to auto resize it
     **/

    /// <summary>
    /// Default dll name
    /// </summary>
    public const string LibraryName = "iphlpapi.dll";


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

    /// <summary>
    /// Pointer to pinned buffer array
    /// </summary>
    private IntPtr _bufferPtr;

    /// <summary>
    /// Pinned buffer array 
    /// </summary>
    private byte[] _bufferArray;

    /// <summary>
    /// GC Handle of buffer array
    /// </summary>
    private GCHandle _bufferGCHandle;

    /// <summary>
    /// Flag indicating whenever IpHelpApiWrapper instance was disposed
    /// </summary>
    public bool Disposed { get; private set; } = false;

    /// <summary>
    /// Gets or sets the flag indicating whenever the buffer should be auto resized if it's not enough to store the results of the external call
    /// </summary>
    public bool AutoResizeBuffer;

    /// <summary>
    /// Gets the Array pool used by the wrapper; if UsedArrayPool is null, no array pool is used
    /// </summary>
    public ArrayPool<byte>? ArrayPool { get; private set; } = null;

    /// <summary>
    /// Shared instance of the wrapper. Uses shared array pool for a buffer
    /// DO NOT DISPOSE
    /// </summary>
    public static readonly IpHelpApiWrapper Shared = new(arrayPool: ArrayPool<byte>.Shared);

    /// <summary>
    /// Default buffer size
    /// </summary>
    public const int DefaultBufferSize = 16 * 1024;


    #region Native functions (Dll imports)

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedTcpTable(ref byte pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedUdpTable(ref byte pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, UdpTableClass tableClass, uint reserved = 0);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetIpNetTable(ref byte pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetIpAddrTable(ref byte pIpAddrTable, ref int pdwSize, bool bOrder);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetIpAddrTable(IntPtr pIpAddrTable, ref int pdwSize, bool bOrder);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetBestInterface(uint dwDestAddr, ref uint pdwBestIfIndex);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetBestInterfaceEx(ref byte dwDestAddr, ref uint pdwBestIfIndex);

    [DllImport(LibraryName, CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
    private static extern uint SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

    #endregion

    /// <summary>
    /// Creates new IpHelpApiWrapper
    /// </summary>
    /// <param name="bufferSize">Size of internal buffer for storing results of external calls</param>
    /// <param name="autoResizeBuffer">If set to true, internal buffer would be auto resized when it's not big enough</param>
    /// <param name="arrayPool">Array pool to get internal byte array buffers; if set to null, allocates new byte array for internal buffer</param>
    public IpHelpApiWrapper(int bufferSize = DefaultBufferSize, bool autoResizeBuffer = true, ArrayPool<byte>? arrayPool = null)
    {
        ArrayPool = arrayPool;
        _bufferArray = (ArrayPool != null) ? ArrayPool.Rent(bufferSize) : new byte[bufferSize];
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
        if (newSize < 0) throw new ArgumentOutOfRangeException(nameof(newSize), "New size must be [0; +inf]");
        lock (_bufferArray)
        {
            _bufferGCHandle.Free();

            if (ArrayPool != null)
            {
                ArrayPool.Return(_bufferArray, true);
                _bufferArray = ArrayPool.Rent(newSize);
            }
            else
            {
                Array.Resize(ref _bufferArray, newSize);
                // Since Array.Resize doesnt actually resize the array and just creates a new one, we would probably still need to re-pin it?
            }
            _bufferGCHandle = GCHandle.Alloc(_bufferArray, GCHandleType.Pinned);
            _bufferPtr = _bufferGCHandle.AddrOfPinnedObject();
        }
    }

    #region TCP Functions

    /// <summary>
    /// Native: GetExtendedTcpTable
    /// Retrieves a table that contains a list of TCP endpoints available to the application
    /// </summary>
    /// <param name="networkType">The version of IP used by the TCP endpoints</param>
    /// <param name="tcpTable">The type of the TCP table structure to retrieve</param>
    /// <param name="sortedOrder">A value that specifies whether the TCP connection table should be sorted</param>
    /// <returns>Returns IEnumerable or records casted down to ITcpRecord</returns>
    /// <exception cref="ArgumentException">Invalid argument: networkType</exception>
    public IEnumerable<ITcpRecord> GetExtendedTcpTable(AddressFamily networkType, TcpTableClass tcpTable, bool sortedOrder = false)
    {
        return networkType switch
        {
            AddressFamily.InterNetwork => this.GetTcp4Connections(tcpTable, sortedOrder).Cast<ITcpRecord>(),
            AddressFamily.InterNetworkV6 => this.GetTcp6Connections(tcpTable, sortedOrder).Cast<ITcpRecord>(),
            _ => throw new ArgumentException("Invalid argument: networkType"),
        };
    }

    #region TCP4 Functions

    public IEnumerable<Tcp4Record> GetTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)
    {
        return tcpTable switch
        {
            TcpTableClass.BasicAll or TcpTableClass.BasicListeners or TcpTableClass.BasicConnections => this.GetBasicTcp4Connections(tcpTable, sortedOrder),
            TcpTableClass.ModuleAll or TcpTableClass.ModuleListeners or TcpTableClass.ModuleConnections => this.GetModuleTcp4Connections(tcpTable, sortedOrder).Cast<Tcp4Record>(),
            TcpTableClass.ProcessAll or TcpTableClass.ProcessListeners or TcpTableClass.ProcessConnections => this.GetProcessTcp4Connections(tcpTable, sortedOrder).Cast<Tcp4Record>(),
            _ => throw new ArgumentException("Invalid argument: tcpTable"),
        };
    }

    #region GetProcessTcp4Connections

    public Tcp4ProcessRecord[] GetProcessTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp4Connections supports only processes");

        return CreateTcp4ProcessRecordArrayFromBuffer(InternalCallAndHandleGetExtendedTcpTable(sortedOrder, AddressFamily.InterNetwork, tcpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static object GetProcessTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp4Connections supports only processes");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedTcpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

        if (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER)
        {
            return bufferSize;
        }

        HandleErrorCode(errorCode);

        return CreateTcp4ProcessRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Tcp4ProcessRecord[] CreateTcp4ProcessRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(buffer);
        Tcp4ProcessRecord[] records = new Tcp4ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    state: (ConnectionState)SpanBitConverter.ToUInt32(buffer, i + 0),
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 4),
                    localPort: (ushort)((buffer[i + 8] << 8) + buffer[i + 9]),
                    remoteAddress: SpanBitConverter.ToUInt32(buffer, i + 12),
                    remotePort: (ushort)((buffer[i + 16] << 8) + buffer[i + 17]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 20)
                );
        }
        return records;
    }

    #endregion

    #region GetModuleTcp4Connections

    public Tcp4ModuleRecord[] GetModuleTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false, bool loadModuleInfo = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp4Connections supports only modules");

        return CreateTcp4ModuleRecordArrayFromBuffer(InternalCallAndHandleGetExtendedTcpTable(sortedOrder, AddressFamily.InterNetwork, tcpTable), new Span<byte>(_bufferArray), loadModuleInfo);
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static object GetModuleTcp4Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false, int bufferSize = DefaultBufferSize, bool loadModuleInfo = false)
    {
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp4Connections supports only modules");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedTcpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

        if (errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER)
        {
            return bufferSize;
        }

        HandleErrorCode(errorCode);

        return CreateTcp4ModuleRecordArrayFromBuffer(bufferSize, buffer, loadModuleInfo);
    }

    private static Tcp4ModuleRecord[] CreateTcp4ModuleRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer, bool loadModuleInfo)
    {
        int singleSize = 160;
        int num = (int)BitConverter.ToUInt32(buffer);
        Tcp4ModuleRecord[] records = new Tcp4ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    state: (ConnectionState)SpanBitConverter.ToUInt32(buffer, i + 0),
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 4),
                    localPort: (ushort)((buffer[i + 8] << 8) + buffer[i + 9]),
                    remoteAddress: SpanBitConverter.ToUInt32(buffer, i + 12),
                    remotePort: (ushort)((buffer[i + 16] << 8) + buffer[i + 17]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 20),
                    createTimestamp: SpanBitConverter.ToInt64(buffer, i + 24),
                    moduleInfo: loadModuleInfo ? MemoryMarshal.Cast<byte, ulong>(buffer.Slice(32, 128)).ToArray() : Array.Empty<ulong>()
                );
        }

        return records;
    }

    #endregion

    #region GetBasicTcp4Connections

    public Tcp4Record[] GetBasicTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.BasicAll or TcpTableClass.BasicConnections or TcpTableClass.BasicListeners)) throw new ArgumentException("GetBasicTcp4Connections supports only basic");

        return CreateTcp4BasicRecordArrayFromBuffer(InternalCallAndHandleGetExtendedTcpTable(sortedOrder, AddressFamily.InterNetwork, tcpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Tcp4Record[] GetBasicTcp4Connections(TcpTableClass tcpTable = TcpTableClass.BasicAll, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (!(tcpTable is TcpTableClass.BasicAll or TcpTableClass.BasicConnections or TcpTableClass.BasicListeners)) throw new ArgumentException("GetBasicTcp4Connections supports only basic");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedTcpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, tcpTable);

        HandleErrorCode(errorCode);

        return CreateTcp4BasicRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Tcp4Record[] CreateTcp4BasicRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 20;
        int num = (int)BitConverter.ToUInt32(buffer);
        Tcp4Record[] records = new Tcp4Record[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    state: (ConnectionState)SpanBitConverter.ToUInt32(buffer, i + 0),
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 4),
                    localPort: (ushort)((buffer[i + 8] << 8) + buffer[i + 9]),
                    remoteAddress: SpanBitConverter.ToUInt32(buffer, i + 12),
                    remotePort: (ushort)((buffer[i + 16] << 8) + buffer[i + 17])
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
            TcpTableClass.ProcessAll or TcpTableClass.ProcessListeners or TcpTableClass.ProcessConnections => this.GetProcessTcp6Connections(tcpTable, sortedOrder).Cast<Tcp6Record>(),
            TcpTableClass.ModuleAll or TcpTableClass.ModuleListeners or TcpTableClass.ModuleConnections => this.GetModuleTcp6Connections(tcpTable, sortedOrder).Cast<Tcp6Record>(),
            _ => throw new ArgumentException("Invalid argument: tcpTable"),
        };
    }

    #region GetProcessTcp6Connections

    public Tcp6ProcessRecord[] GetProcessTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp6Connections supports only processes");

        return CreateTcp6ProcessRecordArrayFromBuffer(InternalCallAndHandleGetExtendedTcpTable(sortedOrder, AddressFamily.InterNetworkV6, tcpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Tcp6ProcessRecord[] GetProcessTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ProcessAll, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (!(tcpTable is TcpTableClass.ProcessAll or TcpTableClass.ProcessConnections or TcpTableClass.ProcessListeners)) throw new ArgumentException("GetProcessTcp6Connections supports only processes");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedTcpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

        HandleErrorCode(errorCode);

        return CreateTcp6ProcessRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Tcp6ProcessRecord[] CreateTcp6ProcessRecordArrayFromBuffer(int allocatedSizem, Span<byte> buffer)
    {
        int singleSize = 56;
        int num = (int)BitConverter.ToUInt32(buffer);
        Tcp6ProcessRecord[] records = new Tcp6ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: buffer[(i + 0)..(i + 16)].ToArray(),
                    localScopeId: SpanBitConverter.ToUInt32(buffer, i + 16),
                    localPort: (ushort)((buffer[i + 20] << 8) + buffer[i + 21]),
                    remoteAddress: buffer[(i + 24)..(i + 40)].ToArray(),
                    remoteScopeId: SpanBitConverter.ToUInt32(buffer, i + 40),
                    remotePort: (ushort)((buffer[i + 44] << 8) + buffer[i + 45]),
                    state: (ConnectionState)SpanBitConverter.ToUInt32(buffer, i + 48),
                    processId: SpanBitConverter.ToInt32(buffer, i + 52)
                );
        }
        return records;
    }

    #endregion

    #region GetModuleTcp6Connections

    public Tcp6ModuleRecord[] GetModuleTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false, bool loadModuleInfo = false)
    {
        ThrowIfDisposed();
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp6Connections supports only modules");

        return CreateTcp6ModuleRecordArrayFromBuffer(InternalCallAndHandleGetExtendedTcpTable(sortedOrder, AddressFamily.InterNetworkV6, tcpTable), new Span<byte>(_bufferArray), loadModuleInfo);
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Tcp6ModuleRecord[] GetModuleTcp6Connections(TcpTableClass tcpTable = TcpTableClass.ModuleAll, bool sortedOrder = false, int bufferSize = DefaultBufferSize, bool loadModuleInfo = false)
    {
        if (!(tcpTable is TcpTableClass.ModuleAll or TcpTableClass.ModuleConnections or TcpTableClass.ModuleListeners)) throw new ArgumentException("GetModuleTcp6Connections supports only modules");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedTcpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, tcpTable);

        HandleErrorCode(errorCode);

        return CreateTcp6ModuleRecordArrayFromBuffer(bufferSize, buffer, loadModuleInfo);
    }

    private static Tcp6ModuleRecord[] CreateTcp6ModuleRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer, bool loadModuleInfo)
    {
        int singleSize = 192;
        int num = (int)BitConverter.ToUInt32(buffer);
        Tcp6ModuleRecord[] records = new Tcp6ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: buffer[(i + 0)..(i + 16)].ToArray(),
                    localScopeId: SpanBitConverter.ToUInt32(buffer, i + 16),
                    localPort: (ushort)((buffer[i + 20] << 8) + buffer[i + 21]),
                    remoteAddress: buffer[(i + 24)..(i + 40)].ToArray(),
                    remoteScopeId: SpanBitConverter.ToUInt32(buffer, i + 40),
                    remotePort: (ushort)((buffer[i + 44] << 8) + buffer[i + 45]),
                    state: (ConnectionState)SpanBitConverter.ToUInt32(buffer, i + 48),
                    processId: SpanBitConverter.ToInt32(buffer, i + 52),
                    createTimestamp: SpanBitConverter.ToInt64(buffer, i + 56),
                    moduleInfo: loadModuleInfo ? MemoryMarshal.Cast<byte, ulong>(buffer.Slice(64, 128)).ToArray() : Array.Empty<ulong>()
                );
        }
        return records;
    }

    #endregion

    #endregion

    #endregion

    #region UDP Functions

    /// <summary>
    /// Native: GetExtendedUdpTabe
    /// Retrieves a table that contains a list of UDP endpoints available to the application.
    /// </summary>
    /// <param name="networkType">The version of IP used by the UDP endpoint</param>
    /// <param name="udpTable">The type of the UDP table structure to retrieve</param>
    /// <param name="sortedOrder">A value that specifies whether the UDP endpoint table should be sorted</param>
    /// <returns>Returns IEnumerable or records casted down to ITcpRecord</returns>
    /// <exception cref="ArgumentException">Invalid argument: networkType</exception>
    public IEnumerable<IUdpRecord> GetExtendedUdpTable(AddressFamily networkType, UdpTableClass udpTable, bool sortedOrder = false)
    {
        return networkType switch
        {
            AddressFamily.InterNetwork => this.GetUdp4Connections(udpTable, sortedOrder).Cast<IUdpRecord>(),
            AddressFamily.InterNetworkV6 => this.GetUdp6Connections(udpTable, sortedOrder).Cast<IUdpRecord>(),
            _ => throw new ArgumentException("Invalid argument: networkType"),
        };
    }

    #region UDP4 Functions

    public IEnumerable<Udp4Record> GetUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        return udpTable switch
        {
            UdpTableClass.Basic => this.GetBasicUdp4Connections(udpTable, sortedOrder),
            UdpTableClass.Module => this.GetModuleUdp4Connections(udpTable, sortedOrder).Cast<Udp4Record>(),
            UdpTableClass.Process => this.GetProcessUdp4Connections(udpTable, sortedOrder).Cast<Udp4Record>(),
            _ => throw new ArgumentException("Invalid argument: udpTable"),
        };
    }

    #region GetProcessUdp4Connections

    public Udp4ProcessRecord[] GetProcessUdp4Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp4Connections supports only processes");

        return CreateUdp4ProcessRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetwork, udpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp4ProcessRecord[] GetProcessUdp4Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp4Connections supports only processes");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp4ProcessRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Udp4ProcessRecord[] CreateUdp4ProcessRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 12;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp4ProcessRecord[] records = new Udp4ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 0),
                    localPort: (ushort)((buffer[i + 4] << 8) + buffer[i + 5]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 8)
                );
        }
        return records;
    }

    #endregion

    #region GetModuleUdp4Connections

    public Udp4ModuleRecord[] GetModuleUdp4Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false, bool loadModuleInfo = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp4Connections supports only modules");

        return CreateUdp4ModuleRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetwork, udpTable), new Span<byte>(_bufferArray), loadModuleInfo);
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp4ModuleRecord[] GetModuleUdp4Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false, int bufferSize = DefaultBufferSize, bool loadModuleInfo = false)
    {
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp4Connections supports only modules");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp4ModuleRecordArrayFromBuffer(bufferSize, buffer, loadModuleInfo);
    }

    private static Udp4ModuleRecord[] CreateUdp4ModuleRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer, bool loadModuleInfo)
    {
        int singleSize = 160;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp4ModuleRecord[] records = new Udp4ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 0),
                    localPort: (ushort)((buffer[i + 4] << 8) + buffer[i + 5]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 8),
                    createTimestamp: SpanBitConverter.ToInt64(buffer, i + 16),
                    specificPortBind: buffer[i + 24] == 1,
                    flags: SpanBitConverter.ToInt32(buffer, i + 28),
                    moduleInfo: loadModuleInfo ? MemoryMarshal.Cast<byte, ulong>(buffer.Slice(32, 128)).ToArray() : Array.Empty<ulong>()
                );
        }
        return records;
    }

    #endregion

    #region GetBasicUdp4Connections

    public Udp4Record[] GetBasicUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp4Connections supports only basic");

        return CreateUdp4BasicRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetwork, udpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp4Record[] GetBasicUdp4Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp4Connections supports only basic");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetwork, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp4BasicRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Udp4Record[] CreateUdp4BasicRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 8;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp4Record[] records = new Udp4Record[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: SpanBitConverter.ToUInt32(buffer, i + 0),
                    localPort: (ushort)((buffer[i + 4] << 8) + buffer[i + 5])
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
            UdpTableClass.Basic => this.GetBasicUdp6Connections(udpTable, sortedOrder),
            UdpTableClass.Module => this.GetModuleUdp6Connections(udpTable, sortedOrder).Cast<Udp6Record>(),
            UdpTableClass.Process => this.GetProcessUdp6Connections(udpTable, sortedOrder).Cast<Udp6Record>(),
            _ => throw new ArgumentException("Invalid argument: udpTable"),
        };
    }

    #region GetProcessUdp6Connections

    public Udp6ProcessRecord[] GetProcessUdp6Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp6Connections supports only processes");

        return CreateUdp6ProcessRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetworkV6, udpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp6ProcessRecord[] GetProcessUdp6Connections(UdpTableClass udpTable = UdpTableClass.Process, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (udpTable is not UdpTableClass.Process) throw new ArgumentException("GetProcessUdp6Connections supports only processes");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp6ProcessRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Udp6ProcessRecord[] CreateUdp6ProcessRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 28;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp6ProcessRecord[] records = new Udp6ProcessRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: buffer[(i + 0)..(i + 16)].ToArray(),
                    localScopeId: SpanBitConverter.ToUInt32(buffer, i + 16),
                    localPort: (ushort)((buffer[i + 20] << 8) + buffer[i + 21]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 24)
                );
        }
        return records;
    }

    #endregion

    #region GetModuleUdp6Connections

    public Udp6ModuleRecord[] GetModuleUdp6Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false, bool loadModuleInfo = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp6Connections supports only modules");

        return CreateUdp6ModuleRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetworkV6, udpTable), new Span<byte>(_bufferArray), loadModuleInfo);
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp6ModuleRecord[] GetModuleUdp6Connections(UdpTableClass udpTable = UdpTableClass.Module, bool sortedOrder = false, int bufferSize = DefaultBufferSize, bool loadModuleInfo = false)
    {
        if (udpTable is not UdpTableClass.Module) throw new ArgumentException("GetModuleUdp6Connections supports only modules");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp6ModuleRecordArrayFromBuffer(bufferSize, buffer, loadModuleInfo);
    }

    private static Udp6ModuleRecord[] CreateUdp6ModuleRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer, bool loadModuleInfo)
    {
        int singleSize = 176;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp6ModuleRecord[] records = new Udp6ModuleRecord[num];
        for (int k = 0, i = 8; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: buffer[(i + 0)..(i + 16)].ToArray(),
                    localScopeId: SpanBitConverter.ToUInt32(buffer, i + 16),
                    localPort: (ushort)((buffer[i + 20] << 8) + buffer[i + 21]),
                    processId: SpanBitConverter.ToInt32(buffer, i + 24),
                    createTimestamp: SpanBitConverter.ToInt64(buffer, i + 32),
                    specificPortBind: buffer[i + 40] == 1,
                    flags: SpanBitConverter.ToInt32(buffer, i + 44),
                    moduleInfo: loadModuleInfo ? MemoryMarshal.Cast<byte, ulong>(buffer.Slice(48, 128)).ToArray() : Array.Empty<ulong>()
                );
        }
        return records;
    }

    #endregion

    #region GetBasicUdp6Connections

    public Udp6Record[] GetBasicUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false)
    {
        ThrowIfDisposed();
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp6Connections supports only basic");

        return CreateUdp6BasicRecordArrayFromBuffer(InternalCallAndHandleGetExtendedUdpTable(sortedOrder, AddressFamily.InterNetworkV6, udpTable), new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Udp6Record[] GetBasicUdp6Connections(UdpTableClass udpTable = UdpTableClass.Basic, bool sortedOrder = false, int bufferSize = DefaultBufferSize)
    {
        if (udpTable is not UdpTableClass.Basic) throw new ArgumentException("GetBasicUdp6Connections supports only basic");
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetExtendedUdpTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder, (int)AddressFamily.InterNetworkV6, udpTable);

        HandleErrorCode(errorCode);

        return CreateUdp6BasicRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static Udp6Record[] CreateUdp6BasicRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(buffer);
        Udp6Record[] records = new Udp6Record[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    localAddress: buffer[(i + 0)..(i + 16)].ToArray(),
                    localScopeId: SpanBitConverter.ToUInt32(buffer, i + 16),
                    localPort: (ushort)((buffer[i + 20] << 8) + buffer[i + 21])
                );
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
        uint errorCode;
        lock (_bufferArray)
        {
            errorCode = GetIpNetTable(_bufferPtr, ref bufferSize, sortedOrder);

            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                BufferSize = bufferSize;
                errorCode = GetIpNetTable(_bufferPtr, ref bufferSize, sortedOrder);
            }
        }

        if (errorCode == (uint)ErrorReturnCodes.ERROR_NO_DATA) return Array.Empty<PhysicalAddressRecord>();
        HandleErrorCode(errorCode);

        return CreatePhysicalAddressRecordArrayFromBuffer(bufferSize, new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static PhysicalAddressRecord[] GetIpNetTableRecords(bool sortedOrder = false, int bufferSize = 1024)
    {
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetIpNetTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder);

        HandleErrorCode(errorCode);

        return CreatePhysicalAddressRecordArrayFromBuffer(bufferSize, buffer);
    }

    private static PhysicalAddressRecord[] CreatePhysicalAddressRecordArrayFromBuffer(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(buffer);
        PhysicalAddressRecord[] records = new PhysicalAddressRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    physicalAddress: buffer[(i + 8)..(i + 14)].ToArray(),
                    ipAddress: SpanBitConverter.ToUInt32(buffer, i + 16),
                    netType: (IpNetType)SpanBitConverter.ToUInt32(buffer, i + 20)
                );
        }
        return records;
    }

    #endregion

    #region GetIpAddrTableRecords

    public InterfaceAddressRecord[] GetIpAddrTableRecords(bool sortedOrder = false)
    {
        ThrowIfDisposed();

        int bufferSize = BufferSize;
        uint errorCode;
        lock (_bufferArray)
        {
            errorCode = GetIpAddrTable(_bufferPtr, ref bufferSize, sortedOrder);
            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                BufferSize = bufferSize;
                errorCode = GetIpAddrTable(_bufferPtr, ref bufferSize, sortedOrder);
            }
        }

        if (errorCode == (uint)ErrorReturnCodes.ERROR_NO_DATA) return Array.Empty<InterfaceAddressRecord>();

        HandleErrorCode(errorCode);

        return CreateInterfaceAddressRecord(bufferSize, new Span<byte>(_bufferArray));
    }

    /// <summary>
    /// Use instance function!
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static InterfaceAddressRecord[] GetIpAddrTableRecords(bool sortedOrder = false, int bufferSize = 512)
    {
        if ((bufferSize > (1023 * 1024)) || (bufferSize < 1)) throw new ArgumentOutOfRangeException(nameof(bufferSize), "bufferSize must be [1; 1047552]");

        Span<byte> buffer = stackalloc byte[bufferSize];

        uint errorCode = GetIpAddrTable(ref buffer.GetPinnableReference(), ref bufferSize, sortedOrder);

        HandleErrorCode(errorCode);

        return CreateInterfaceAddressRecord(bufferSize, buffer);
    }

    private static InterfaceAddressRecord[] CreateInterfaceAddressRecord(int allocatedSize, Span<byte> buffer)
    {
        int singleSize = 24;
        int num = (int)BitConverter.ToUInt32(buffer);
        InterfaceAddressRecord[] records = new InterfaceAddressRecord[num];
        for (int k = 0, i = 4; k < num; k++, i += singleSize)
        {
            records[k] = new
                (
                    ipAddress: SpanBitConverter.ToUInt32(buffer, i),
                    interfaceIndex: SpanBitConverter.ToUInt32(buffer, i + 4),
                    mask: SpanBitConverter.ToUInt32(buffer, i + 8),
                    broadcastAddress: SpanBitConverter.ToUInt32(buffer, i + 12),
                    maxReassembleSize: SpanBitConverter.ToUInt32(buffer, i + 16)
                );
        }
        return records;
    }

    #endregion

    #region GetBestInterfaceIndex()

    /// <summary>
    /// Native: GetBestInterface
    /// Retrieves the index of the interface that has the best route to the specified IPv4 address
    /// (IPv4 only)
    /// </summary>
    /// <param name="address">The destination IPv4 address for which to retrieve the interface that has the best route</param>
    /// <returns>Index of the interface that has the best route to the specified IPv4 address</returns>
    public static uint GetBestInterfaceIndex(uint address)
    {
        uint index = 0;
        uint errorCode = GetBestInterface(address, ref index);
        HandleErrorCode(errorCode);
        return index;
    }

    /// <summary>
    /// Native: GetBestInterface
    /// Retrieves the index of the interface that has the best route to the specified IPv4 address
    /// (IPv4 only)
    /// </summary>
    /// <param name="address">The destination IPv4 address for which to retrieve the interface that has the best route</param>
    /// <returns>Index of the interface that has the best route to the specified IPv4 address</returns>
    public static uint GetBestInterfaceIndex(IPAddress address)
    {
        return GetBestInterfaceIndex(GetIPV4AddressUint(address));
    }

    #endregion

    #region GetBestInterface4()

    /// <summary>
    /// Retrieves NetworkInterface that has the best route to the specified IPv4 address
    /// (IPv4 only)
    /// </summary>
    /// <param name="address">The destination IPv4 address for which to retrieve the NetworkInteface that has the best route</param>
    /// <param name="interfaces">Array of NetworkInterfaces to search in, if set to null searches in all network interfaces</param>
    /// <returns>NetworkInterface that has the best route to the specified IPv4 address out of all provided interfaces</returns>
    /// <exception cref="InvalidOperationException">Unable to find the best interface</exception>
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

    /// <summary>
    /// Native: GetBestInterfaceEx
    /// Retrieves the index of the interface that has the best route to the specified IPv4 or IPv6 address.
    /// </summary>
    /// <param name="address">The destination IPv6 or IPv4 address for which to retrieve the interface with the best route</param>
    /// <returns>Index of the interface with the best route to the specified IPv6 or IPv4 address</returns>
    /// <exception cref="InvalidDataException">Unable to get ip address bytes</exception>
    public static uint GetBestInterfaceIndexEx(IPAddress address)
    {
        Span<byte> byteSpan = stackalloc byte[26];

        byteSpan[0] = (byte)(((short)address.AddressFamily) & 255);
        byteSpan[1] = (byte)(((short)address.AddressFamily) >> 8);

        if (!address.TryWriteBytes(byteSpan[2..], out int _)) throw new InvalidDataException("Unable to get ip address bytes");

        uint index = 0;
        uint errorCode = GetBestInterfaceEx(ref byteSpan.GetPinnableReference(), ref index);
        HandleErrorCode(errorCode);
        return index;
    }

    #endregion

    #region GetBestInterface6()

    /// <summary>
    /// Retrieves NetworkInterface that has the best route to the specified IPv6 address
    /// (IPv6 only)
    /// </summary>
    /// <param name="address">The destination IPv6 address for which to retrieve the NetworkInteface that has the best route</param>
    /// <param name="interfaces">Array of NetworkInterfaces to search in, if set to null searches in all network interfaces</param>
    /// <returns>NetworkInterface that has the best route to the specified IPv6 address out of all provided interfaces</returns>
    /// <exception cref="InvalidOperationException">Unable to find the best interface</exception>

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

    /// <summary>
    /// Retrieves NetworkInterface that has the best route to the specified address
    /// </summary>
    /// <param name="address">The destination address for which to retrieve the NetworkInteface that has the best route</param>
    /// <param name="interfaces">Array of NetworkInterfaces to search in, if set to null searches in all network interfaces</param>
    /// <returns>NetworkInterface that has the best route to the specified address out of all provided interfaces</returns>
    /// <exception cref="InvalidOperationException">Unable to find the best interface</exception>
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

    /// <summary>
    /// Native: SendARP
    /// Sends an Address Resolution Protocol (ARP) request to obtain the physical address that corresponds to the specified destination IPv4 address.
    /// (IPv4 only)
    /// </summary>
    /// <param name="destionationAddress">The destination IPv4 address, ARP request attempts to obtain the physical address that corresponds to this IPv4 address</param>
    /// <param name="sourceAddress">The source IPv4 address of the sender, this parameter is optional and is used to select the interface to send the request on for the ARP entry</param>
    /// <param name="physicalAddressSize">Maximum buffer size, in bytes, the application has set aside to receive the physical address or MAC address (>= 6 bytes)</param>
    /// <returns>Resolved physical address</returns>
    public static byte[] SendARP(uint destionationAddress, uint sourceAddress = 0, int physicalAddressSize = 6)
    {
        byte[] physicalAddress = new byte[physicalAddressSize];
        int addressLength = physicalAddress.Length;
        uint errorCode = SendARP(destionationAddress, sourceAddress, physicalAddress, ref addressLength);
        HandleErrorCode(errorCode);
        return physicalAddress;
    }

    /// <summary>
    /// Native: SendARP
    /// Sends an Address Resolution Protocol (ARP) request to obtain the physical address that corresponds to the specified destination IPv4 address.
    /// (IPv4 only)
    /// </summary>
    /// <param name="destAddress">The destination IPv4 address, ARP request attempts to obtain the physical address that corresponds to this IPv4 address</param>
    /// <param name="srcAddress">The source IPv4 address of the sender, this parameter is optional and is used to select the interface to send the request on for the ARP entry</param>
    /// <param name="physicalAddressSize">Maximum buffer size, in bytes, the application has set aside to receive the physical address or MAC address (>= 6 bytes)</param>
    /// <returns>Resolved physical address</returns>
    public static PhysicalAddress SendARP(IPAddress destAddress, IPAddress? srcAddress = null, int physicalAddressSize = 6)
    {
        // Do not check if addresses are IPv4 since GetIPV4AddressUint would throw an exception if not IPv4 address was passed to it
        uint destionationAddress = GetIPV4AddressUint(destAddress);
        uint sourceAddress = ((srcAddress == null) ? 0 : GetIPV4AddressUint(srcAddress));

        return new PhysicalAddress(SendARP(destionationAddress, sourceAddress, physicalAddressSize));
    }

    #endregion

    /// <summary>
    /// Calls GetExtendedTcpTable and writes results to buffer, handles any exceptions and auto resizing
    /// </summary>
    /// <param name="sortedOrder">bOrder parameter of the call</param>
    /// <param name="addrFamily">ulAf parameter of the call</param>
    /// <param name="tcpTable">tableClass parameter of the call</param>
    /// <returns>Size allocated by the call</returns>
    private int InternalCallAndHandleGetExtendedTcpTable(bool sortedOrder, AddressFamily addrFamily, TcpTableClass tcpTable)
    {
        int bufferSize = BufferSize;
        uint errorCode;
        lock (_bufferArray)
        {
            errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)addrFamily, tcpTable);
            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                BufferSize = bufferSize;
                errorCode = GetExtendedTcpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)addrFamily, tcpTable);
            }
        }
        HandleErrorCode(errorCode);
        return bufferSize;
    }

    /// <summary>
    /// Calls GetExtendedUdpTable and writes results to buffer, handles any exceptions and auto resizing
    /// </summary>
    /// <param name="sortedOrder">bOrder parameter of the call</param>
    /// <param name="addrFamily">ulAf parameter of the call</param>
    /// <param name="udpTable">tableClass parameter of the call</param>
    /// <returns>Size allocated by the call</returns>
    private int InternalCallAndHandleGetExtendedUdpTable(bool sortedOrder, AddressFamily addrFamily, UdpTableClass udpTable)
    {
        int bufferSize = BufferSize;
        uint errorCode;
        lock (_bufferArray)
        {
            errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)addrFamily, udpTable);
            while ((errorCode == (uint)ErrorReturnCodes.ERROR_INSUFFICIENT_BUFFER) && AutoResizeBuffer)
            {
                BufferSize = bufferSize;
                errorCode = GetExtendedUdpTable(_bufferPtr, ref bufferSize, sortedOrder, (int)addrFamily, udpTable);
            }
        }
        HandleErrorCode(errorCode);
        return bufferSize;
    }

    /// <summary>
    /// Returns ipv4 address in uint format
    /// </summary>
    /// <param name="ipAddr">Address to convert</param>
    /// <returns>Address in uint format</returns>
    /// <exception cref="InvalidOperationException">Provided ip address is not ipv4</exception>
    /// <exception cref="InvalidDataException">Unable to write ip address bytes</exception>
    public static uint GetIPV4AddressUint(IPAddress ipAddr)
    {
        if (ipAddr.AddressFamily is not AddressFamily.InterNetwork) throw new InvalidOperationException("GetIPV4AddressUint supports only ipv4 addresses");
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

    ~IpHelpApiWrapper()
    {
        if (!Disposed)
            Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        /**
         * Free GCHandle for buffer
         * Return array pool if necessary
         **/
        if (Disposed)
        {
            return;
        }

        _bufferGCHandle.Free();
        if (ArrayPool != null)
        {
            // Not sure if we need to clear the array btw
            ArrayPool.Return(_bufferArray, true);
        }

        ArrayPool = null;
        _bufferPtr = IntPtr.Zero;
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        _bufferArray = null;
#pragma warning restore CS8625

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

    /// <summary>
    /// Module info, if not loaded is empty array
    /// </summary>
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

    /// <summary>
    /// Module info, if not loaded is empty array
    /// </summary>
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

    /// <summary>
    /// Module info, if not loaded is empty array
    /// </summary>
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

    /// <summary>
    /// Module info, if not loaded is empty array
    /// </summary>
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

public sealed class InterfaceAddressRecord
{

    public readonly uint IpAddressInt;

    private IPAddress? _ipAddress;

    public IPAddress IPAddress
    {
        get
        {
            _ipAddress ??= new IPAddress(IpAddressInt);
            return _ipAddress;
        }
    }

    public readonly uint InterfaceIndex;

    public readonly uint Mask;

    public readonly uint BroadcastAddressInt;

    private IPAddress? _broadcastAddress;

    public IPAddress BroadcastAddress
    {
        get
        {
            _broadcastAddress ??= new IPAddress(BroadcastAddressInt);
            return _broadcastAddress;
        }
    }

    public readonly uint MaxReassembleSize;

    public InterfaceAddressRecord(uint ipAddress, uint interfaceIndex, uint mask, uint broadcastAddress, uint maxReassembleSize)
    {
        IpAddressInt = ipAddress;
        InterfaceIndex = interfaceIndex;
        Mask = mask;
        BroadcastAddressInt = broadcastAddress;
        MaxReassembleSize = maxReassembleSize;
    }
}

/// <summary>
/// Provides span bit conversions with indexes (BitConverter doesnt support indexes)
/// I am not sure how should it be done properly, maybe extension?
/// </summary>
internal sealed class SpanBitConverter
{

    public static int ToInt32<TFrom>(Span<TFrom> span, int index = 0)
        where TFrom : struct
    {
        return MemoryMarshal.Cast<TFrom, int>(span.Slice(index, sizeof(Int32)))[0];
    }

    public static long ToInt64<TFrom>(Span<TFrom> span, int index = 0)
        where TFrom : struct
    {
        return MemoryMarshal.Cast<TFrom, long>(span.Slice(index, sizeof(Int64)))[0];
    }

    public static uint ToUInt32<TFrom>(Span<TFrom> span, int index = 0)
        where TFrom : struct
    {
        return MemoryMarshal.Cast<TFrom, uint>(span.Slice(index, sizeof(UInt32)))[0];
    }

    public static TTo CastToSingle<TFrom, TTo>(Span<TFrom> span, int size, int index = 0)
        where TFrom : struct
        where TTo : struct
    {
        return MemoryMarshal.Cast<TFrom, TTo>(span.Slice(index, size))[0];
    }
}