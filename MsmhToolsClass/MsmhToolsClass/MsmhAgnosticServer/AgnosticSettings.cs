﻿using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

#nullable enable
namespace MsmhToolsClass.MsmhAgnosticServer;

/// <summary>
/// Server Settings.
/// </summary>
public class AgnosticSettings
{
    public enum WorkingMode
    {
        Dns,
        DnsAndProxy
    }

    private int PListenerPort { get; set; } = 53;
    /// <summary>
    /// The Port On Which To Listen.
    /// </summary>
    public int ListenerPort
    {
        get => PListenerPort;
        set
        {
            if (value < 0 || value > 65535) throw new ArgumentOutOfRangeException(nameof(ListenerPort));
            PListenerPort = value;
        }
    }

    public WorkingMode Working_Mode { get; set; } = WorkingMode.DnsAndProxy;

    private int PMaxRequests { get; set; } = 10000;
    /// <summary>
    /// Maximum Number Of Threads Per Second. (Min: 20)
    /// </summary>
    public int MaxRequests
    {
        get => PMaxRequests;
        set
        {
            PMaxRequests = value >= MsmhAgnosticServer.MaxRequestsDivide ? value : MsmhAgnosticServer.MaxRequestsDivide;
        }
    }

    /// <summary>
    /// Cancel Dns Request if didn't receive data for n seconds. Default: 5 Sec
    /// </summary>
    public int DnsTimeoutSec { get; set; } = 5;

    /// <summary>
    /// Kill Proxy Request if didn't receive data for n seconds. Default: 40 Sec ( 0 = Disabled)
    /// </summary>
    public int ProxyTimeoutSec { get; set; } = 40;

    /// <summary>
    /// Kill Proxy Requests If CPU Usage is Higher than this Value. (Windows Only)
    /// </summary>
    public float KillOnCpuUsage { get; set; } = 40;

    public bool BlockPort80 { get; set; } = false;

    public bool AllowInsecure { get; set; } = false;

    public List<string> DNSs { get; set; } = new();
    public string? CloudflareCleanIP { get; set; }

    private IPAddress PBootstrapIpAddress { get; set; } = IPAddress.None;
    public IPAddress BootstrapIpAddress
    {
        get => PBootstrapIpAddress;
        set => PBootstrapIpAddress = value;
    }

    private int PBootstrapPort { get; set; } = 53;
    public int BootstrapPort
    {
        get => PBootstrapPort;
        set
        {
            if (value < 0 || value > 65535) throw new ArgumentOutOfRangeException(nameof(BootstrapPort));
            PBootstrapPort = value;
        }
    }

    /// <summary>
    /// Only HTTP And Socks5 Are Supported
    /// </summary>
    public string? UpstreamProxyScheme { get; set; }
    public string? UpstreamProxyUser { get; set; }
    public string? UpstreamProxyPass { get; set; }
    public bool ApplyUpstreamOnlyToBlockedIps { get; set; }

    // Default DNSs
    public static List<string> DefaultDNSs()
    {
        return new List<string>()
        {
            "tcp://8.8.8.8:53",
            "tcp://1.1.1.1:53",
            "udp://9.9.9.9:9953",
            //"system"
        };
    }

    public bool IsIPv4SupportedByOS { get; private set; }
    public bool IsIPv6SupportedByOS { get; private set; }
    public bool IsIPv4SupportedByISP { get; private set; }
    public bool IsIPv6SupportedByISP { get; private set; }
    public IPAddress? ListenerIP { get; private set; }
    public IPEndPoint ServerEndPoint { get; internal set; } = new(IPAddress.None, 0);
    public string ServerUdpDnsAddress { get; internal set; } = string.Empty;
    public string ServerTcpDnsAddress { get; internal set; } = string.Empty;
    public string ServerDohDnsAddress { get; internal set; } = string.Empty;
    public string ServerHttpProxyAddress { get; internal set; } = string.Empty;
    public string ServerSocks5ProxyAddress { get; internal set; } = string.Empty;

    public AgnosticSettings()
    {
        IsIPv4SupportedByISP = true;
        IsIPv6SupportedByISP = true;
        
        IsIPv4SupportedByOS = NetworkTool.IsIPv4SupportedByOS();
        IsIPv6SupportedByOS = NetworkTool.IsIPv6SupportedByOS();

        ListenerIP = IsIPv6SupportedByOS ? IPAddress.IPv6Any : IsIPv4SupportedByOS ? IPAddress.Any : null;
    }

    public async Task InitializeAsync()
    {
        try
        {
            if (OperatingSystem.IsWindows()) ProcessManager.ExecuteOnly("ipconfig", null, "/flushdns", true, true);
            //IsIPv4SupportedByISP = await NetworkTool.IsIpProtocolSupportedByISPAsync(BootstrapIpAddress.ToStringNoScopeId(), 6000);
            //IsIPv6SupportedByISP = await NetworkTool.IsIpProtocolSupportedByISPAsync("2001:4860:4860::8888", 6000);

            if (ListenerIP != null) ServerEndPoint = new(ListenerIP, ListenerPort);

            ServerUdpDnsAddress = NetworkTool.IpToUrl("udp", IPAddress.Loopback, ListenerPort, string.Empty);
            ServerTcpDnsAddress = NetworkTool.IpToUrl("tcp", IPAddress.Loopback, ListenerPort, string.Empty);
            ServerDohDnsAddress = NetworkTool.IpToUrl("https", IPAddress.Loopback, ListenerPort, "dns-query");
            ServerHttpProxyAddress = NetworkTool.IpToUrl("http", IPAddress.Loopback, ListenerPort, string.Empty);
            ServerSocks5ProxyAddress = NetworkTool.IpToUrl("socks5", IPAddress.Loopback, ListenerPort, string.Empty);

            if (ServerEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                ServerUdpDnsAddress = NetworkTool.IpToUrl("udp", IPAddress.IPv6Loopback, ListenerPort, string.Empty);
                ServerTcpDnsAddress = NetworkTool.IpToUrl("tcp", IPAddress.IPv6Loopback, ListenerPort, string.Empty);
                ServerDohDnsAddress = NetworkTool.IpToUrl("https", IPAddress.IPv6Loopback, ListenerPort, "dns-query");
                ServerHttpProxyAddress = NetworkTool.IpToUrl("http", IPAddress.IPv6Loopback, ListenerPort, string.Empty);
                ServerSocks5ProxyAddress = NetworkTool.IpToUrl("socks5", IPAddress.IPv6Loopback, ListenerPort, string.Empty);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("AgnosticSettings Initialize: " + ex.Message);
        }
    }
}