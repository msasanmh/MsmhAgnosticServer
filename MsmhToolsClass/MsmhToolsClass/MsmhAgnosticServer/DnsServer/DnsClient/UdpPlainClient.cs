﻿using System.Net.Sockets;
using System.Net;

namespace MsmhToolsClass.MsmhAgnosticServer;

public class UdpPlainClient
{
    private byte[] QueryBuffer { get; set; } = Array.Empty<byte>();
    private DnsReader Reader { get; set; } = new();
    private int TimeoutMS { get; set; } = 5;
    private CancellationToken CT { get; set; }

    public UdpPlainClient(byte[] queryBuffer, DnsReader reader, int timeoutMS, CancellationToken cT)
    {
        QueryBuffer = queryBuffer;
        Reader = reader;
        TimeoutMS = timeoutMS;
        CT = cT;
    }

    public async Task<byte[]> GetResponseAsync()
    {
        byte[] result = Array.Empty<byte>();

        Task task = Task.Run(async () =>
        {
            try
            {
                IPEndPoint ep = new(IPAddress.Parse(Reader.Host), Reader.Port);

                Socket socket = new(ep.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
                {
                    SendTimeout = TimeoutMS,
                    ReceiveTimeout = TimeoutMS
                };

                try
                {
                    await socket.ConnectAsync(ep, CT).ConfigureAwait(false);
                    await socket.SendAsync(QueryBuffer, SocketFlags.None, CT).ConfigureAwait(false);
                    byte[] buffer = new byte[MsmhAgnosticServer.MaxUdpDnsDataSize];
                    int receivedLength = await socket.ReceiveAsync(buffer, SocketFlags.None, CT).ConfigureAwait(false);

                    if (receivedLength > 0) result = buffer[..receivedLength];
                }
                catch (Exception) { }

                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
                socket.Dispose();
            }
            catch (Exception) { }
        });
        try { await task.WaitAsync(TimeSpan.FromMilliseconds(TimeoutMS), CT).ConfigureAwait(false); } catch (Exception) { }

        return result;
    }
}