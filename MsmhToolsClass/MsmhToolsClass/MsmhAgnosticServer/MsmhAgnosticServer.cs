﻿using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
// MSMH Agnostic Server - CopyRight GPLv3 MSasanMH (msasanmh@gmail.com) 2023 - 2025

namespace MsmhToolsClass.MsmhAgnosticServer;

public partial class MsmhAgnosticServer
{
    //======================================= Fragment Support
    public AgnosticProgram.Fragment FragmentProgram = new();
    public void EnableFragment(AgnosticProgram.Fragment fragmentProgram)
    {
        FragmentProgram = fragmentProgram;
    }

    //======================================= Rules Support
    public AgnosticProgram.Rules RulesProgram = new();
    public void EnableRules(AgnosticProgram.Rules rules)
    {
        RulesProgram = rules;
    }

    //======================================= DnsLimit Support
    public AgnosticProgram.DnsLimit DnsLimitProgram = new();
    public void EnableDnsLimit(AgnosticProgram.DnsLimit dnsLimit)
    {
        DnsLimitProgram = dnsLimit;
    }

    // ====================================== Const
    internal static readonly int MaxDataSize = 65536;
    internal static readonly int MaxUdpDnsDataSize = 1024; // 512 Without IP Or UDP Header
    internal static readonly int MaxTcpDnsDataSize = 64000;
    internal static readonly int MaxByteArraySize_SingleDimension = 2147483591;
    internal static readonly int MaxByteArraySize_OtherTypes = 2146435071;
    internal static readonly string DnsMessageContentType = "application/dns-message";
    internal static readonly string ODnsMessageContentType = "application/oblivious-dns-message";
    internal static readonly int DNS_HEADER_LENGTH = 12;
    internal static readonly SslProtocols SSL_Protocols = SslProtocols.None | SslProtocols.Tls12 | SslProtocols.Tls13;
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "<Pending>")]
    internal static bool Callback(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;

    //======================================= Start Server
    internal AgnosticSettings Settings_ = new();
    public AgnosticSettingsSSL SettingsSSL_ { get; internal set; } = new(false);

    private Thread? MainThread;
    private Socket? UdpSocket_;
    private TcpListener? TcpListener_;

    private readonly ConcurrentQueue<DateTime> MaxRequestsQueue = new();
    internal static readonly int MaxRequestsDelay = 50;
    internal static readonly int MaxRequestsDivide = 20; // 20 * 50 = 1000 ms
    private readonly CaptivePortal CaptivePortals = new();
    private readonly DnsCache DnsCaches = new();
    private readonly ProxyRequestsCache ProxyRequestsCaches = new();
    private readonly ConcurrentDictionary<string, (DateTime dt, bool applyFakeSNI, bool applyFragment)> TestRequests = new();
    internal TunnelManager TunnelManager_ = new();
    public Stats Stats { get; private set; } = new();

    private float CpuUsage { get; set; } = -1;
    private static NetworkTool.InternetState InternetState = NetworkTool.InternetState.Unknown; // Default

    public event EventHandler<EventArgs>? OnRequestReceived;
    public event EventHandler<EventArgs>? OnDebugInfoReceived;
    
    public bool IsRunning { get; private set; } = false;
    private bool IsReady { get; set; } = false;

    private CancellationTokenSource? CTS;
    private CancellationToken CT;
    private bool Cancel { get; set; } = false;
    private CancellationTokenSource? CTS_PR;

    public MsmhAgnosticServer() { }

    public async Task EnableSSLAsync(AgnosticSettingsSSL settingsSSL)
    {
        SettingsSSL_ = settingsSSL;
        await SettingsSSL_.Build().ConfigureAwait(false);
    }

    public async Task StartAsync(AgnosticSettings settings)
    {
        try
        {
            if (IsRunning) return;
            IsRunning = true;

            Stopwatch stopwatch = Stopwatch.StartNew();
            Settings_ = settings;
            await Settings_.InitializeAsync();

            // Set Default DNSs
            if (Settings_.DNSs.Count == 0) Settings_.DNSs = AgnosticSettings.DefaultDNSs();

            Welcome(true, TimeSpan.Zero);

            CTS = new();
            CT = CTS.Token;
            Cancel = false;

            TunnelManager_ = new();
            Stats = new();

            MaxRequestsTimer();
            KillOnOverloadTimer();

            ThreadStart threadStart = new(AcceptConnections);
            MainThread = new(threadStart);
            if (OperatingSystem.IsWindows()) MainThread.SetApartmentState(ApartmentState.STA);
            MainThread.Start();

            // Wait
            Task wait = Task.Run(async () =>
            {
                while (true)
                {
                    if (IsRunning && IsReady) break;
                    await Task.Delay(20);
                }
            });
            try { await wait.WaitAsync(TimeSpan.FromSeconds(20)); } catch (Exception) { }

            stopwatch.Stop();
            Welcome(false, stopwatch.Elapsed);
        }
        catch (Exception ex)
        {
            Debug.WriteLine("MsmhAgnosticServer StartAsync: " + ex.Message);
        }
    }

    private void Welcome(bool isStarting, TimeSpan timeSpan)
    {
        try
        {
            // Event
            string state = isStarting ? "Starting" : "Started";
            string msgEvent = $"Server {state} On Port: {Settings_.ListenerPort}";
            if (timeSpan != TimeSpan.Zero) msgEvent += $", Took: {ConvertTool.TimeSpanToHumanRead(timeSpan, true)}";
            OnRequestReceived?.Invoke(msgEvent, EventArgs.Empty);
            OnDebugInfoReceived?.Invoke(msgEvent, EventArgs.Empty);
        }
        catch (Exception) { }
    }

    private async void MaxRequestsTimer()
    {
        await Task.Run(async () =>
        {
            while (true)
            {
                if (Cancel) break;
                await Task.Delay(MaxRequestsDelay);
                
                try
                {
                    bool peek = MaxRequestsQueue.TryPeek(out DateTime dt);
                    if (peek)
                    {
                        double diff = (DateTime.UtcNow - dt).TotalMilliseconds;
                        if (diff > 1000 / MaxRequestsDivide) // Dequeue If Older Than 50 ms (1000 / 20)
                            MaxRequestsQueue.TryDequeue(out _);
                    }
                }
                catch (Exception) { }
            }
        });
    }

    private async void KillOnOverloadTimer()
    {
        await Task.Run(async () =>
        {
            while (true)
            {
                if (Cancel) break;
                await Task.Delay(5000);

                try
                {
                    if (OperatingSystem.IsWindows() && typeof(PerformanceCounter) != null)
                        CpuUsage = await ProcessManager.GetCpuUsageAsync(Environment.ProcessId, 1000);

                    if (CpuUsage >= Settings_.KillOnCpuUsage && Settings_.KillOnCpuUsage > 0)
                    {
                        KillAll();
                    }

                    if (CpuUsage >= 75f)
                    {
                        try { Environment.Exit(0); } catch (Exception) { }
                        await ProcessManager.KillProcessByPidAsync(Environment.ProcessId);
                    }

                    // Get Internet State
                    IPAddress ipToCheck = Settings_.BootstrapIpAddress;
                    if (ipToCheck == IPAddress.None || ipToCheck == IPAddress.Any || ipToCheck == IPAddress.IPv6None || ipToCheck == IPAddress.IPv6Any)
                    {
                        bool isIP = IPAddress.TryParse("8.8.8.8", out IPAddress? ip);
                        if (isIP && ip != null) ipToCheck = ip;
                    }
                    InternetState = await NetworkTool.GetInternetStateAsync(ipToCheck, null, 6000);
                }
                catch (Exception) { }
            }
        });
    }

    /// <summary>
    /// Kill All Active Requests
    /// </summary>
    public void KillAll()
    {
        try
        {
            CTS_PR?.Cancel();
            ProxyRequestsCaches.Clear();
            TunnelManager_?.KillAllRequests();
        }
        catch (Exception ex)
        {
            Debug.WriteLine("MsmhAgnosticServer KillAll: " + ex.Message);
        }
    }

    public void Stop()
    {
        if (IsRunning)
        {
            try
            {
                IsRunning = false;
                IsReady = false;
                CTS?.Cancel();
                Cancel = true;
                UdpSocket_?.Shutdown(SocketShutdown.Both);
                UdpSocket_?.Dispose();
                TcpListener_?.Stop();
                TcpListener_ = null;

                KillAll();

                MaxRequestsQueue.Clear();
                DnsCaches.Flush();
                ProxyRequestsCaches.Clear();
                TestRequests.Clear();

                Goodbye();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Stop MsmhAgnosticServer: " + ex.GetInnerExceptions());
            }
        }
    }

    private void Goodbye()
    {
        // Event
        string msgEvent = "Proxy Server Stopped.";
        OnRequestReceived?.Invoke(msgEvent, EventArgs.Empty);
        OnDebugInfoReceived?.Invoke(msgEvent, EventArgs.Empty);
    }

    public int ListeningPort => Settings_.ListenerPort;
    public bool IsFragmentActive => FragmentProgram.FragmentMode != AgnosticProgram.Fragment.Mode.Disable;
    public bool IsFakeSniActive => SettingsSSL_.EnableSSL && SettingsSSL_.ChangeSni;
    public int ActiveProxyTunnels => TunnelManager_.Count;
    public int MaxRequests => Settings_.MaxRequests;
    public int CachedDnsRequests => DnsCaches.CachedRequests;

    public void FlushDnsCache()
    {
        DnsCaches.Flush();
    }

    private async void AcceptConnections()
    {
        if (Cancel) return;

        try
        {
            if (Settings_.ListenerIP == null)
            {
                string msgEventErr = "Neither IPv4 Nor IPv6 Is Supported By Your OS!";
                Debug.WriteLine(msgEventErr);
                OnRequestReceived?.Invoke(msgEventErr, EventArgs.Empty);
                Stop();
                return;
            }

            // EndPoint
            IPEndPoint ipEndPoint = Settings_.ServerEndPoint;

            // Make Port Free
            if (OperatingSystem.IsWindows())
            {
                List<int> pids = await ProcessManager.GetProcessPidsByUsingPortAsync(Settings_.ListenerPort);
                foreach (int pid in pids) await ProcessManager.KillProcessByPidAsync(pid);
                await Task.Delay(5);
                pids = await ProcessManager.GetProcessPidsByUsingPortAsync(Settings_.ListenerPort);
                foreach (int pid in pids) await ProcessManager.KillProcessByPidAsync(pid);
            }

            // UDP
            UdpSocket_ = new(ipEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (ipEndPoint.Address.Equals(IPAddress.IPv6Any))
            {
                UdpSocket_.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, 0);
                UdpSocket_.DualMode = true;
            }
            UdpSocket_.Bind(ipEndPoint);

            // TCP
            TcpListener_ = new(ipEndPoint);
            SocketOptionName socketOptionName = SocketOptionName.ReuseAddress | SocketOptionName.ReuseUnicastPort;
            TcpListener_.Server.SetSocketOption(SocketOptionLevel.Socket, socketOptionName, true);
            if (ipEndPoint.Address.Equals(IPAddress.IPv6Any))
            {
                TcpListener_.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, 0);
                TcpListener_.Server.DualMode = true;
            }
            TcpListener_.Start();

            if (UdpSocket_ != null && TcpListener_ != null)
            {
                // Wait For Bound
                bool isBound = false;
                Task wait = Task.Run(async () =>
                {
                    while (true)
                    {
                        isBound = UdpSocket_.IsBound && TcpListener_.Server.IsBound;
                        if (isBound) break;
                        await Task.Delay(20);
                    }
                });
                try { await wait.WaitAsync(TimeSpan.FromSeconds(1)); } catch (Exception) { }

                if (!isBound)
                {
                    string msgEventErr = "ERROR: Accept Connections: UDP Or TCP Socket Is Not Bound.";
                    Debug.WriteLine(msgEventErr);
                    OnRequestReceived?.Invoke(msgEventErr, EventArgs.Empty);
                    Stop();
                    return;
                }

                // Run UDP & TCP Listener In Parallel
                udp(UdpSocket_);
                tcp(TcpListener_);

                await Task.Delay(20);
                IsReady = true;

                // UDP
                async void udp(Socket udpSocket)
                {
                    while (!Cancel)
                    {
                        try
                        {
                            byte[] buffer = new byte[MaxDataSize];
                            SocketReceiveMessageFromResult udpMessage = await udpSocket.ReceiveMessageFromAsync(buffer, SocketFlags.None, ipEndPoint).ConfigureAwait(false);
                            if (CpuUsage < Settings_.KillOnCpuUsage || Settings_.KillOnCpuUsage <= 0)
                            {
                                if (udpMessage.ReceivedBytes > 0)
                                {
                                    buffer = buffer[..udpMessage.ReceivedBytes];
                                    //Debug.WriteLine(" UDP ===> " + BitConverter.ToString(buffer));
                                    AgnosticRequest agnosticRequest = new()
                                    {
                                        Udp_Socket = udpSocket,
                                        Local_EndPoint = udpSocket.LocalEndPoint as IPEndPoint,
                                        Remote_EndPoint = udpMessage.RemoteEndPoint as IPEndPoint,
                                        Peeked_Buffer = buffer,
                                        Protocol = AgnosticRequest.ListenerProtocol.UDP
                                    };

                                    ProcessConnectionSync(agnosticRequest);
                                }
                            }
                            if (CT.IsCancellationRequested || Cancel) break;
                        }
                        catch (Exception ex)
                        {
                            // Event Error
                            if (!Cancel)
                            {
                                string msgEventErr = $"ERROR: Accept Connections UDP: {ex.GetInnerExceptions()}";
                                Debug.WriteLine(msgEventErr);
                                OnDebugInfoReceived?.Invoke(msgEventErr, EventArgs.Empty);
                            }
                        }
                    }
                }

                // TCP
                async void tcp(TcpListener tcpListener)
                {
                    while (!Cancel)
                    {
                        try
                        {
                            TcpClient tcpClient = await tcpListener.AcceptTcpClientAsync().ConfigureAwait(false);
                            if (CpuUsage < Settings_.KillOnCpuUsage || Settings_.KillOnCpuUsage <= 0)
                            {
                                byte[] buffer = new byte[MaxDataSize];
                                int received = await tcpClient.Client.ReceiveAsync(buffer, SocketFlags.Peek).ConfigureAwait(false);
                                if (received > 0)
                                {
                                    tcpClient.NoDelay = true;
                                    buffer = buffer[..received];
                                    //Debug.WriteLine(" TCP ===> " + BitConverter.ToString(buffer));
                                    AgnosticRequest agnosticRequest = new()
                                    {
                                        Tcp_Client = tcpClient,
                                        Local_EndPoint = tcpClient.Client.LocalEndPoint as IPEndPoint,
                                        Remote_EndPoint = tcpClient.Client.RemoteEndPoint as IPEndPoint,
                                        Peeked_Buffer = buffer,
                                        Protocol = AgnosticRequest.ListenerProtocol.TCP
                                    };

                                    ProcessConnectionSync(agnosticRequest);
                                }
                            }
                            if (CT.IsCancellationRequested || Cancel) break;
                        }
                        catch (Exception ex)
                        {
                            // Event Error
                            if (!Cancel)
                            {
                                string msgEventErr = $"ERROR: Accept Connections TCP: {ex.GetInnerExceptions()}";
                                Debug.WriteLine(msgEventErr);
                                OnDebugInfoReceived?.Invoke(msgEventErr, EventArgs.Empty);
                            }
                        }
                    }
                }
            }
            else
            {
                string msgEventErr = "ERROR: Accept Connections: UdpSocket Or TcpListener Was NULL.";
                Debug.WriteLine(msgEventErr);
                OnRequestReceived?.Invoke(msgEventErr, EventArgs.Empty);
                Stop();
            }
        }
        catch (Exception ex)
        {
            // Event Error
            if (!Cancel)
            {
                string msgEventErr = $"ERROR: Accept Connections: {ex.GetInnerExceptions()}";
                Debug.WriteLine(msgEventErr);
                OnRequestReceived?.Invoke(msgEventErr, EventArgs.Empty);
                Stop();
            }
        }
    }

    private void ProcessConnectionSync(AgnosticRequest agnosticRequest)
    {
        Task.Run(() => ClientConnected(agnosticRequest));
    }

    private async void ClientConnected(AgnosticRequest aRequest)
    {
        if (aRequest.Local_EndPoint == null || aRequest.Remote_EndPoint == null)
        {
            aRequest.Disconnect();
            return;
        }

        // Count Max Requests
        try
        {
            MaxRequestsQueue.Enqueue(DateTime.UtcNow);
            if (Settings_.MaxRequests >= MaxRequestsDivide)
            {
                if (MaxRequestsQueue.Count >= Settings_.MaxRequests / MaxRequestsDivide) // Check for 50 ms (1000 / 20)
                {
                    // Event
                    string blockEvent = $"Recevied {MaxRequestsQueue.Count * MaxRequestsDivide} Requests Per Second - Request Denied Due To Max Requests of {Settings_.MaxRequests}.";
                    Debug.WriteLine("====================> " + blockEvent);
                    OnRequestReceived?.Invoke(blockEvent, EventArgs.Empty);
                    aRequest.Disconnect();
                    return;
                }
            }
        }
        catch (Exception) { }

        // Generate unique int
        int connectionId;
        try
        {
            connectionId = Guid.NewGuid().GetHashCode() + BitConverter.ToInt32(Guid.NewGuid().ToByteArray(), 0);
        }
        catch (Exception)
        {
            connectionId = Guid.NewGuid().GetHashCode();
        }
        
        AgnosticResult aResult = await aRequest.GetResultAsync(SettingsSSL_).ConfigureAwait(false);
        
        if (aResult.Socket == null || aResult.FirstBuffer.Length == 0 || aResult.Protocol == RequestProtocol.Unknown)
        {
            aRequest.Disconnect();
            return;
        }

        //Debug.WriteLine("Request ListenerProtocol ===> " + aResult.Protocol);
        //Debug.WriteLine("Request Buffer ===> " + BitConverter.ToString(aResult.FirstBuffer));
        
        if (aResult.Protocol == RequestProtocol.UDP ||
            aResult.Protocol == RequestProtocol.TCP ||
            aResult.Protocol == RequestProtocol.DoH)
        {
            // ===== Process DNS
            await DnsTunnel.Process(aResult, RulesProgram, DnsLimitProgram, DnsCaches, Settings_, OnRequestReceived);
            aRequest.Disconnect();
        }
        else
        {
            // ===== Process Proxy
            if (Settings_.Working_Mode == AgnosticSettings.WorkingMode.DnsAndProxy)
            {
                // Create Client
                ProxyClient proxyClient = new(aResult.Socket);

                // Create Request
                CTS_PR = new();
                ProxyRequest? req = null;
                if (aResult.Protocol == RequestProtocol.HTTP_S)
                    req = await ProxyRequest.RequestHTTP_S(aResult.FirstBuffer, CTS_PR.Token).ConfigureAwait(false);
                else if (aResult.Protocol == RequestProtocol.SOCKS4_4A)
                    req = await ProxyRequest.RequestSocks4_4A(proxyClient, aResult.FirstBuffer, CTS_PR.Token).ConfigureAwait(false);
                else if (aResult.Protocol == RequestProtocol.SOCKS5)
                    req = await ProxyRequest.RequestSocks5(proxyClient, aResult.FirstBuffer, CTS_PR.Token).ConfigureAwait(false);
                else if (aResult.Protocol == RequestProtocol.SniProxy)
                    req = await ProxyRequest.RequestSniProxy(aResult.SNI, Settings_.ListenerPort, CTS_PR.Token).ConfigureAwait(false);
                
                // Apply Programs
                req = await ApplyPrograms(aResult.Local_EndPoint.Address, req).ConfigureAwait(false);
                
                if (req == null)
                {
                    aRequest.Disconnect();
                    return;
                }
                
                // Create Tunnel
                ProxyTunnel proxyTunnel = new(connectionId, proxyClient, req, SettingsSSL_);
                proxyTunnel.Open();

                proxyTunnel.OnTunnelDisconnected += ProxyTunnel_OnTunnelDisconnected;
                proxyTunnel.OnDataReceived += ProxyTunnel_OnDataReceived;

                TunnelManager_.Add(proxyTunnel);
            }
        }
    }

    private void ProxyTunnel_OnTunnelDisconnected(object? sender, EventArgs e)
    {
        try
        {
            if (sender is not ProxyTunnel pt) return;

            if (pt.KillOnTimeout.IsRunning)
            {
                pt.KillOnTimeout.Reset();
                pt.KillOnTimeout.Stop();
            }

            pt.OnTunnelDisconnected -= ProxyTunnel_OnTunnelDisconnected;
            pt.OnDataReceived -= ProxyTunnel_OnDataReceived;
            pt.ClientSSL?.Disconnect();

            TunnelManager_.Remove(pt);
            Debug.WriteLine($"{pt.Req.Address} Disconnected");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("ProxyTunnel_OnTunnelDisconnected: " + ex.Message);
        }
    }

    private void ProxyTunnel_OnDataReceived(object? sender, EventArgs e)
    {
        try
        {
            if (sender is not ProxyTunnel t) return;

            t.Client.OnDataReceived += async (s, e) =>
            {
                // Client Received == Remote Sent
                if (!t.KillOnTimeout.IsRunning) t.KillOnTimeout.Start();
                t.KillOnTimeout.Restart();
                if (e.Buffer.Length > 0)
                {
                    if (t.Req.ApplyFragment)
                        await SendAsync(e.Buffer, t);
                    else
                        await t.RemoteClient.SendAsync(e.Buffer).ConfigureAwait(false);

                    lock (Stats)
                    {
                        Stats.AddBytes(e.Buffer.Length, ByteType.Sent);
                    }
                }
                
                t.KillOnTimeout.Restart();
                await t.Client.StartReceiveAsync().ConfigureAwait(false);
                t.KillOnTimeout.Restart();
            };

            t.Client.OnDataSent += (s, e) =>
            {
                // Client Sent == Remote Received
                if (!t.KillOnTimeout.IsRunning) t.KillOnTimeout.Start();
                t.KillOnTimeout.Restart();
                lock (Stats)
                {
                    Stats.AddBytes(e.Buffer.Length, ByteType.Received);
                }
            };

            t.RemoteClient.OnDataReceived += async (s, e) =>
            {
                t.KillOnTimeout.Restart();

                if (e.Buffer.Length > 0)
                    await t.Client.SendAsync(e.Buffer).ConfigureAwait(false);

                t.KillOnTimeout.Restart();
                await t.RemoteClient.StartReceiveAsync().ConfigureAwait(false);
                t.KillOnTimeout.Restart();
            };
            
            // Handle SSL
            if (t.ClientSSL != null)
            {
                t.ClientSSL.OnClientDataReceived += (s, e) =>
                {
                    t.KillOnTimeout.Restart();
                    
                    if (e.Buffer.Length > 0)
                    {
                        // Can't be implement here. Ex: "The WriteAsync method cannot be called when another write operation is pending"
                        //await t.ClientSSL.RemoteStream.WriteAsync(e.Buffer).ConfigureAwait(false);

                        lock (Stats)
                        {
                            Stats.AddBytes(e.Buffer.Length, ByteType.Sent);
                        }
                    }
                    t.ClientSSL.OnClientDataReceived -= null;
                };
                
                t.ClientSSL.OnRemoteDataReceived += (s, e) =>
                {
                    t.KillOnTimeout.Restart();

                    if (e.Buffer.Length > 0)
                    {
                        // Can't be implement here. Ex: "The WriteAsync method cannot be called when another write operation is pending"
                        //await t.ClientSSL.ClientStream.WriteAsync(e.Buffer).ConfigureAwait(false);

                        lock (Stats)
                        {
                            Stats.AddBytes(e.Buffer.Length, ByteType.Received);
                        }
                    }
                    t.ClientSSL.OnRemoteDataReceived -= null;
                };
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("ProxyTunnel_OnDataReceived: " + ex.Message);
        }
    }

    private async Task SendAsync(byte[] data, ProxyTunnel t)
    {
        try
        {
            if (t.RemoteClient.Socket_ != null && t.RemoteClient.Socket_.Connected)
            {
                AgnosticProgram.Fragment bp = FragmentProgram;
                bp.DestHostname = t.Req.Address;
                bp.DestPort = t.Req.Port;
                if (bp.FragmentMode == AgnosticProgram.Fragment.Mode.Program)
                {
                    AgnosticProgram.Fragment.ProgramMode programMode = new(data, t.RemoteClient.Socket_);
                    await programMode.SendAsync(bp);
                }
                else
                    await t.RemoteClient.Socket_.SendAsync(data, SocketFlags.None).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Send: " + ex.Message);
        }
    }

}