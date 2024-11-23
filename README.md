### A DNS and Proxy Server in C# (Class Library .NET 6)

_I'm just sharing this library for developers due to recieved requests.
It's a multi platform DNS and Proxy Server. Target Platform: Windows.
Tested once on Android. You can make it fully compatible with your own target platform._

* v1.6.7: DoH Client fixed for Android.

[Library Directory Address.](https://github.com/msasanmh/MsmhAgnosticServer/tree/main/MsmhToolsClass/MsmhToolsClass/MsmhAgnosticServer)

DNS Servers: DNS-Over-UDP, DNS-Over-TCP, DNS-Over-HTTPS (DoH)\
DNS Clients: DNS-Over-UDP, DNS-Over-TCP, DNS-Over-HTTPS (DoH)(https://, h3://), DNS-Over-TLS (DoT), DNSCrypt, Anonymized DNSCrypt.\
Proxy Servers:\
    HTTP (Domain, IPv4, IPv6) (Get, Post, etc)\
    HTTPS (Domain, IPv4, IPv6) (Post, etc)\
    SOCKS4 (IPv4) (Connect, Bind)\
    SOCKS4A (Domain, IPv4) (Connect, Bind)\
    SOCKS5 (Domain, IPv4, IPv6) (Connect, Bind, UDP)

DNS Server Features: DNS Records modification, Upstream Proxy, Text based DNS Rules (Block, Fake DNS, Upstream Proxy per domain)\
Proxy Server Features: Upstream Proxy, Fragment, Fake SNI, Text based Proxy Rules (Block, Fake DNS, Fake SNI, Custom DNS, Upstream Proxy per domain)\

Smart DNS Server: Supported - You can create an Smart DNS Server using DNS Rules (Just modify all A Records and AAAA Records To Your Proxy Server IP).\
Limit DoH By Path: Supported - e.g. https://example.com/UserName/dns-query </br>

Running a DNS and Proxy Server on port 8080 example:
```C#
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
    "h3://max.rethinkdns.com/dns-query",
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

// Enable Rules
AgnosticProgram.Rules rules = new();
await rules.SetAsync(AgnosticProgram.Rules.Mode.File, "File_Path");
server.EnableRules(rules);

// Enable DNS Limit Program e.g. https://127.0.0.1:8080/dns-query and https://127.0.0.1:8080/UserName/dns-query
AgnosticProgram.DnsLimit dnsLimit = new();
string allowedDohPaths = "dns-query\nUserName";
dnsLimit.Set(true, false, AgnosticProgram.DnsLimit.LimitDoHPathsMode.Text, allowedDohPaths);
server.EnableDnsLimit(dnsLimit);

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
```

