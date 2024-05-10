using MsmhToolsClass.MsmhAgnosticServer;
using System.Net;

namespace ConsoleAppTest;

internal class Program
{
    static async Task Main()
    {
        // Server Library Path:
        // MsmhToolsClass/MsmhAgnosticServer/MsmhAgnosticServer.cs

        // Create Agnostic Server
        MsmhAgnosticServer server = new();

        // Request Received Event
        server.OnRequestReceived += Server_OnRequestReceived;

        // A List Of DNS Servers To Connect To
        List<string> dnsServers = new()
        {
            "sdns://AQMAAAAAAAAAEjEwMy44Ny42OC4xOTQ6ODQ0MyAxXDKkdrOao8ZeLyu7vTnVrT0C7YlPNNf6trdMkje7QR8yLmRuc2NyeXB0LWNlcnQuZG5zLmJlYmFzaWQuY29t",
            "tcp://8.8.8.8:53",
            "tcp://1.1.1.1:53",
            "https://max.rethinkdns.com/dns-query",
            "https://45.90.29.204:443/dns-query",
            "udp://208.67.222.222:5353"
        };

        // Create Settings For Server
        AgnosticSettings settings = new()
        {
            Working_Mode = AgnosticSettings.WorkingMode.DnsAndProxy, // Working Mode - Only DNS Or DNS And Proxy
            ListenerPort = 8080, // Server Listning Port
            DnsTimeoutSec = 10, // DNS Request Timeout In Seconds
            ProxyTimeoutSec = 40, // Proxy Request Timeout In Seconds
            MaxRequests = 1000000, // Set Number Of Requests To Handle Per Second
            KillOnCpuUsage = 40, // Kill All Proxy Requests If CPU Usage Goes Above 40%
            DNSs = dnsServers, // Set Our DNS Servers List
            BootstrapIpAddress = IPAddress.Parse("8.8.8.8"), // Set Bootstrap IP Address
            BootstrapPort = 53, // Set Bootstrap Port
            AllowInsecure = false, // Allow Insecure
            BlockPort80 = false, // Block Port 80 On Proxy Requests
            // CloudflareCleanIP = cfClenIP, // You Can Redirect All Cloudflare IPs To A Clean IP (IPv4 Only)
            // UpstreamProxyScheme = $"socks5://{IPAddress.Loopback}:53", // You Can Set Your Upstream Proxy Here
            // ApplyUpstreamOnlyToBlockedIps = true // Apply Upstream Proxy Only To Blocked IPs
        };

        // Enable Fragment For Proxy Requests
        AgnosticProgram.Fragment fragment = new();
        fragment.Set(AgnosticProgram.Fragment.Mode.Program, 50, AgnosticProgram.Fragment.ChunkMode.SNI, 5, 2, 1);
        server.EnableFragment(fragment);

        //// Enable DNS Rules
        //AgnosticProgram.DnsRules dnsRules = new();
        //dnsRules.Set(AgnosticProgram.DnsRules.Mode.File, "File_Path");
        //server.EnableDnsRules(dnsRules);

        //// Enable Proxy Rules
        //AgnosticProgram.ProxyRules proxyRules = new();
        //proxyRules.Set(AgnosticProgram.ProxyRules.Mode.File, "File_Path");
        //server.EnableProxyRules(proxyRules);

        // Create SSL Settings For Activating DoH And HTTPS Server, Also You Can Change SNI Here (Fake SNI)
        AgnosticSettingsSSL settingsSSL = new(true)
        {
            EnableSSL = true,
            //ChangeSni = true,
            //DefaultSni = "speedtest.net",
        };
        
        await server.EnableSSL(settingsSSL);

        // Start Server
        server.Start(settings);

        // Write To Console
        Console.WriteLine($"Msmh Agnostic Server Started On: {settings.ListenerIP}:{settings.ListenerPort}");

        // To Stop Server
        //server.Stop();


        // Keep Console Open
        Console.ReadLine();
    }

    private static void Server_OnRequestReceived(object? sender, EventArgs e)
    {
        if (sender is not string msg) return;
        Console.WriteLine(msg);
    }
}