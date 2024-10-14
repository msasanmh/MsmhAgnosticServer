﻿using System.Net;

namespace MsmhToolsClass.MsmhAgnosticServer;

public static class Bootstrap
{
    public static async Task<string> GetDnsIpAsync(string domain, IPAddress bootstrapIP, int bootstrapPort, int timeoutSec, bool getIPv6, string? proxyScheme = null, string? proxyUser = null, string? proxyPass = null)
    {
        string domainIP = domain;
        bool isIP = NetworkTool.IsIP(domain, out _);
        if (!isIP)
        {
            if (bootstrapIP == IPAddress.None || bootstrapIP == IPAddress.IPv6None || bootstrapPort < 1)
            {
                IPAddress ip = GetIP.GetIpFromSystem(domain, getIPv6, true);
                if (ip != IPAddress.None && ip != IPAddress.IPv6None) domainIP = ip.ToString();
            }
            else
            {
                string bootstrap;
                if (NetworkTool.IsIPv6(bootstrapIP))
                    bootstrap = $"tcp://[{bootstrapIP}]:{bootstrapPort}"; // TCP Usually Don't Get Hijack! - IPv6
                else
                    bootstrap = $"tcp://{bootstrapIP}:{bootstrapPort}"; // TCP Usually Don't Get Hijack! - IPv4
                IPAddress ip = await GetIP.GetIpFromDnsAddressAsync(domain, bootstrap, false, timeoutSec, getIPv6, IPAddress.None, 0, proxyScheme, proxyUser, proxyPass);
                if (ip != IPAddress.None && ip != IPAddress.IPv6None) domainIP = ip.ToString();
            }
        }
        return domainIP;
    }
}