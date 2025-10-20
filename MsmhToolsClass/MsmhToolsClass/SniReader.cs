﻿using System.Diagnostics;
using System.Security.Authentication;
using System.Text;

namespace MsmhToolsClass;

// https://tls13.xargs.org
public class SniReader
{
    public class Lengths
    {
        public int TLS_Record_Layer_StartIndex_2Bytes { get; set; } = -1;
        public int TLS_Record_Layer_Length { get; set; } = -1;
        public int Client_Hello_StartIndex_3Bytes { get; set; } = -1;
        public int Client_Hello_Length { get; set; } = -1;
        public int Extensions_StartIndex_2Bytes { get; set; } = -1;
        public int Extensions_Length { get; set; } = -1;
    }

    public class TlsExtensions
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public int StartIndex { get; set; } = -1;
        public int Length { get; set; } = -1;
    }

    public class SniExtension
    {
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public int StartIndex { get; set; } = -1;
        public int Length { get; set; } = -1;
    }

    public class SNI
    {
        public string ServerName { get; set; } = string.Empty;
        public byte[] Data { get; set; } = Array.Empty<byte>();
        public int StartIndex { get; set; } = -1;
        public int Length { get; set; } = -1;
    }

    public string ReasonPhrase { get; private set; } = string.Empty;
    public SslProtocols SslProtocol { get; private set; } = SslProtocols.None;
    public Lengths AllLengths { get; private set; } = new();
    public bool HasSniPaddingExtension { get; private set; } = false;
    public bool HasTlsExtensions { get; private set; } = false;
    public TlsExtensions AllExtensions { get; private set; } = new();
    public bool HasSniExtension { get; private set; } = false;
    public List<SniExtension> SniExtensionList { get; private set; } = new();
    public bool HasSni { get; private set; } = false;
    public List<SNI> SniList { get; private set; } = new();
    public bool IsAClientHello { get; private set; } = false;
    public bool IsHandshakeWithoutSNI { get; private set; } = false;
    public byte[] Data { get; private set; } = Array.Empty<byte>();

    private const int TLS_HEADER_LEN = 5;
    private const int TLS_HANDSHAKE_CONTENT_TYPE = 0x16;
    private const int TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;

    public SniReader(byte[] data)
    {
        try
        {
            Data = data;
            int pos = TLS_HEADER_LEN;
            int dataLength = data.Length;

            if (dataLength < TLS_HEADER_LEN)
            {
                ReasonPhrase = "TCP Payload Is Not Large Enough For A TLS Header.";
                return;
            }

            // RECORD HEADER
            if (data[0] == 1 & 0x80 == 1 && data[2] == 1)
            {
                ReasonPhrase = "Received SSL 2.0 Client Hello Which Can Not Support SNI.";
#pragma warning disable CS0618 // Type or member is obsolete
                SslProtocol = SslProtocols.Ssl2;
#pragma warning restore CS0618 // Type or member is obsolete
                return;
            }
            else
            {
                if (data[0] != TLS_HANDSHAKE_CONTENT_TYPE)
                {
                    ReasonPhrase = "Request Did Not Begin With TLS Handshake.";
                    return;
                }

                int tls_version_major = data[1];
                int tls_version_minor = data[2];

#pragma warning disable CS0618 // Type or member is obsolete
                if (tls_version_minor == 0 && tls_version_major == 3) SslProtocol = SslProtocols.Ssl3;
#pragma warning restore CS0618 // Type or member is obsolete
                if (tls_version_minor == 1 && tls_version_major == 0) SslProtocol = SslProtocols.Tls;
                if (tls_version_minor == 1 && tls_version_major == 1) SslProtocol = SslProtocols.Tls11;
                if (tls_version_minor == 1 && tls_version_major == 2) SslProtocol = SslProtocols.Tls12;
                if (tls_version_minor == 1 && tls_version_major == 3) SslProtocol = SslProtocols.Tls13;

                if (tls_version_major < 3)
                {
                    ReasonPhrase = $"Received SSL Handshake Cannot Support SNI. Min TLS: {tls_version_minor} Max TLS: {tls_version_major}";
                    IsHandshakeWithoutSNI = true;
                    return;
                }

                // TLS Record Layer Length (Length Of Handshake Message) (2 Bytes) ======================================
                int len = (data[3] << 8) + data[4];
                AllLengths.TLS_Record_Layer_StartIndex_2Bytes = 3;
                AllLengths.TLS_Record_Layer_Length = len;
                //Debug.WriteLine("Length Of TLS Record Layer: " + len);
                dataLength = Math.Min(dataLength, len + TLS_HEADER_LEN);

                // Check We Received Entire TLS Record Length
                if (dataLength < len + TLS_HEADER_LEN)
                {
                    ReasonPhrase = "Didn't Receive Entire TLS Record Length.";
                    return;
                }

                // HANDSHAKE HEADER
                if (pos + 1 > dataLength)
                {
                    ReasonPhrase = "Handshake Error.";
                    return;
                }

                // data[5] == 0x01
                if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
                {
                    ReasonPhrase = "Not A Client Hello.";
                    return;
                }
                else
                {
                    IsAClientHello = true;
                }

                // Skip Handshake Message Type
                pos += 1;

                // Length Of Client Hello (Handshake) (3 Bytes) ======================================
                len = (data[pos] << 16) + (data[pos + 1] << 8) + data[pos + 2];
                AllLengths.Client_Hello_StartIndex_3Bytes = pos;
                AllLengths.Client_Hello_Length = len;
                //Debug.WriteLine("Length Of Client Hello: " + len);

                // Skip Length Of Client Hello Data
                pos += 3;

                // CLIENT VERSION (This Field Is No Longer Used For Negotiation And Is Hardcoded To The 1.2 Version)
                pos += 2;

                // CLIENT RANDOM (32 Bytes Constant)
                pos += 32;

                // SESSION ID
                if (pos + 1 > dataLength)
                {
                    ReasonPhrase = "Session ID Error.";
                    return;
                }

                // Session ID Length (1 Byte)
                len = data[pos];
                //Debug.WriteLine("Length Of Session ID: " + len);
                pos += 1 + len;

                // CIPHER SUITES
                if (pos + 2 > dataLength)
                {
                    ReasonPhrase = "Cipher Suit Error.";
                    return;
                }

                // Cipher Suits Length (2 Bytes)
                len = (data[pos] << 8) + data[pos + 1];
                //Debug.WriteLine("Length Of Cipher Suits: " + len);
                pos += 2 + len;

                // COMPRESSION METHODS (TLS 1.3 No Longer Allows Compression, So This Field Is Always A Single Entry.
                // 01 - 1 Bytes Of Compression Methods. 00 - Assigned Value For "null" Compression.)
                if (pos + 1 > dataLength)
                {
                    ReasonPhrase = "Compression Method Error.";
                    return;
                }

                // Compression Methods Length (1 Byte)
                len = data[pos];
                //Debug.WriteLine("Length Of Compression Methods: " + len);
                pos += 1 + len;

                if (pos == dataLength && tls_version_major == 3 && tls_version_minor == 0)
                {
                    ReasonPhrase = "Received SSL 3.0 Handshake Without Extensions.";
                    IsHandshakeWithoutSNI = true;
                    return;
                }

                // EXTENSIONS
                if (pos + 2 > dataLength)
                {
                    ReasonPhrase = "Extensions Error.";
                    return;
                }

                // Extensions Length (2 Bytes) ======================================
                len = (data[pos] << 8) + data[pos + 1];
                AllLengths.Extensions_StartIndex_2Bytes = pos;
                AllLengths.Extensions_Length = len;
                //Debug.WriteLine("Length Of Extensions: " + len);
                pos += 2;
                
                if (pos + len > dataLength)
                {
                    ReasonPhrase = "Wrong Data.";
                    return;
                }

                byte[] extensionsData = new byte[len];
                Buffer.BlockCopy(data, pos, extensionsData, 0, extensionsData.Length);

                ParseExtensions(extensionsData, pos);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("SniReader: " + ex.Message);
        }
    }

    private void ParseExtensions(byte[] data, int pos0)
    {
        try
        {
            if (data.Length <= 0) return;

            HasTlsExtensions = true;
            AllExtensions.Data = data;
            AllExtensions.Length = data.Length;
            AllExtensions.StartIndex = pos0;

            int pos = 0;
            int len;

            // Parse Each 4 Bytes For The Extension Header (To Avoid Index Out Of Range)
            while (pos + 4 <= data.Length)
            {
                len = 2; // Add Extension Type
                len += 2; // Add Extension Length (2 Bytes)

                // Add SNI Extension Data
                len += (data[pos + 2] << 8) + data[pos + 3];

                byte[] extData = new byte[len];
                Buffer.BlockCopy(data, pos, extData, 0, len);

                if (data[pos] == 0x00 && data[pos + 1] == 0x00) // Extension: SNI
                    ParseSniExtension(extData, pos0 + pos);
                else if (data[pos] == 0x00 && data[pos + 1] == 0x15) // Extension: Padding
                    HasSniPaddingExtension = true;
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x0b) // Extension: EC Point Formats
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x0a) // Extension: Supported Groups
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x23) // Extension: Session Ticket
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x16) // Extension: Encrypt-Then-MAC
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x17) // Extension: Extended Master Secret
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x0d) // Extension: Signature Algorithms
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x2b) // Extension: Supported Versions
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x2d) // Extension: PSK Key Exchange Modes
                //else if (data[pos] == 0x00 && data[pos + 1] == 0x33) // Extension: Key Share

                // Advance to the next extension
                pos += len;
            }

            if (SniList.Any() && !string.IsNullOrWhiteSpace(SniList[0].ServerName))
            {
                HasSni = true;
                ReasonPhrase = "Successfully Read SNI.";
            }
            else
            {
                HasSni = false;
                ReasonPhrase = "A Handshake Without SNI.";
                SniList.Clear();
                IsHandshakeWithoutSNI = true;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("SniReader ParseExtensions: " + ex.Message);
        }
    }

    private void ParseSniExtension(byte[] data, int pos0)
    {
        try
        {
            // EXTENSION SERVER NAME
            if (data.Length <= 0) return;

            // Google SNI Extension e.g.
            //byte[] google = new byte[23];
            //google[0] = 0;
            //google[1] = 0;
            //google[2] = 0;
            //google[3] = 19;
            //google[4] = 0;
            //google[5] = 17;
            //google[6] = 0;
            //google[7] = 0;
            //google[8] = 14;
            //byte[] googleSNI = Encoding.UTF8.GetBytes("www.google.com");

            HasSniExtension = true;
            SniExtension sniExtension = new()
            {
                Data = data,
                Length = data.Length,
                StartIndex = pos0
            };
            SniExtensionList.Add(sniExtension);
            //Debug.WriteLine("=========R: " + (sniExtension.StartIndex + sniExtension.Length));
            int pos = 0;

            // Check If It's A Server Name Extension
            if (data[pos] == 0x00 && data[pos + 1] == 0x00)
            {
                pos += 2; // Skip Server Name List Length (00 00)
                int len;

                while (pos + 1 < data.Length)
                {
                    // SNI Extension Data Length (2 Bytes)
                    len = (data[pos] << 8) + data[pos + 1];
                    pos += 2;

                    // First And Only List Entry Length (2 Bytes)
                    len = (data[pos] << 8) + data[pos + 1];
                    pos += 2; // Skip Extension Header

                    // List Entry Type - 0x00 Is DNS Hostname (1 Byte)
                    if (data[pos] == 0x00)
                    {
                        pos += 1; // Skip List Entry Type

                        // Hostname Length (2 Bytes)
                        len = (data[pos] << 8) + data[pos + 1];
                        pos += 2; // Skip Hostname Length

                        if (pos + len > data.Length) break;

                        if (len > 0)
                        {
                            byte[] outData = new byte[len];
                            Buffer.BlockCopy(data, pos, outData, 0, len);

                            string serverName = Encoding.UTF8.GetString(outData);
                            //Debug.WriteLine("----------Server Name: " + serverName + ", Length: " + len + ", Whole Data Length: " + Data.Length);

                            SNI sni = new()
                            {
                                Data = outData,
                                Length = len,
                                ServerName = serverName,
                                StartIndex = pos0 + pos
                            };

                            // Add SNI to List
                            SniList.Add(sni);
                        }
                    }
                    else
                    {
                        Debug.WriteLine("SniReader: Unknown server name extension name type.");
                    }

                    pos += len; // Skip Hostname
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("SniReader ParseSniExtension: " + ex.Message);
        }
    }

}