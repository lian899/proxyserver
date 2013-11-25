using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SuperSocket.SocketBase.Protocol;
using SuperSocket.SocketBase;
using SuperSocket.Common;
using System.Net;
using System.IO;
using System.Text.RegularExpressions;
using System.Net.Sockets;
using System.Threading;
using SuperSocket.ClientEngine;

namespace SuperSocket.ProxyServer
{
    enum SocksState
    {
        NotAuthenticated,
        Authenticating,
        Authenticated,
        FoundLength,
        Connected
    }
    class Socks5ProxyReceiveFilter : ReceiveFilterBase<BinaryRequestInfo>
    {

        protected static readonly BinaryRequestInfo NullRequestInfo;

        private ProxySession m_Session;
        private SocksState m_State = SocksState.NotAuthenticated;


        public string UserName
        {
            get;
            private set;
        }
        public string Password
        {
            get;
            private set;
        }

        /// <summary>
        /// Whether to need to verify identity
        /// </summary>
        public bool RequireValidate
        {
            get
            {
                return !string.IsNullOrEmpty(this.UserName) || !string.IsNullOrEmpty(this.Password);
            }
        }

        /// <summary>
        /// Be connected the remote end of the address
        /// </summary>
        private IPEndPoint RemoteEndPoint { get; set; }

        private TcpClient Proxy { get; set; }

        public Socks5ProxyReceiveFilter(ProxySession session)
        {
            m_Session = session;
        }

        public Socks5ProxyReceiveFilter(ProxySession session, string userName, string password)
            : this(session)
        {
            //m_Session = session;
            this.UserName = userName;
            this.Password = password;
        }

        public override BinaryRequestInfo Filter(byte[] readBuffer, int offset, int length, bool toBeCopied, out int rest)
        {
            if (m_State == SocksState.NotAuthenticated)
            {
                ArraySegmentList buffer = new ArraySegmentList();
                buffer.AddSegment(readBuffer, offset, length, toBeCopied);
                if (!DoShakeHands(buffer.ToArrayData()))
                    m_Session.Close();
                rest = 0;
                return null;
            }
            if (m_State == SocksState.Authenticating)
            {
                ArraySegmentList buffer = new ArraySegmentList();
                buffer.AddSegment(readBuffer, offset, length, toBeCopied);
                if (!ValidateIdentity(buffer.ToArrayData()))
                    m_Session.Close();
                rest = 0;
                return null;
            }
            if (m_State == SocksState.Authenticated)
            {
                ArraySegmentList buffer = new ArraySegmentList();
                buffer.AddSegment(readBuffer, offset, length, toBeCopied);
                if (!DoProtocolRequest(buffer.ToArrayData()))
                    m_Session.Close();
                else
                    CreateProxyBridge();
                rest = 0;
                return null;
            }
            if (m_State == SocksState.Connected)
            {
                ArraySegmentList buffer = new ArraySegmentList();
                buffer.AddSegment(readBuffer, offset, length, toBeCopied);
                Proxy.Client.Send(buffer.ToArrayData());
                rest = 0;
                return null;
            }

            rest = 0;
            //NextReceiveFilter = new ProxyDataReceiveFilter(m_Session);
            return null;

        }

        /// <summary>
        /// Process ShakeHands
        /// </summary>
        private bool DoShakeHands(byte[] buffer)
        {

            byte method = 0xFF; 
            if (buffer.Length >= 2)
            {
                //if need verify
                if (this.RequireValidate)
                {
                    //need verify,so whether the client supports the user name and password authentication
                    foreach (byte b in buffer)
                    {
                        if (b == 0x02)
                            method = 0x02;   //client supports the user name and password authentication
                    }
                    m_State = SocksState.Authenticating;
                }
                else
                {
                    //don't need to verify
                    method = 0x00;
                    m_State = SocksState.Authenticated;
                }
            }
            byte[] returnBuffer = new byte[] { 0x05, method };
            //send to client
            m_Session.Send(returnBuffer, 0, returnBuffer.Length);
            return (method != 0xFF);
        }


        /// <summary>
        /// Process authentication
        /// </summary>
        private bool ValidateIdentity(byte[] buffer)
        {
            byte ep = 0xFF;//0xFF -> 255
            string username = string.Empty, password = string.Empty;

            //报文格式:0x01 | 用户名长度（1字节）| 用户名（长度根据用户名长度域指定） | 口令长度（1字节） | 口令（长度由口令长度域指定）
            if (buffer.Length >= 2)
            {
                int offset = 1;
                int stringLength = 0;

                //if username is null
                if (buffer[1] == 0x00)
                {
                    if (string.IsNullOrEmpty(this.UserName))
                    {
                        ep = 0x00;  //say username is null
                    }
                }
                else
                {
                    stringLength = buffer[offset];
                    username = Encoding.ASCII.GetString(buffer, offset + 1, stringLength);
                    offset = offset + stringLength + 1;
                    if (!string.IsNullOrEmpty(this.UserName))
                    {
                        ep = (byte)(username.Equals(this.UserName) ? 0x00 : 0xFF);
                    }
                }

                if (ep == 0x00)
                {
                    ep = 0xFF;
                    if (buffer[0] == 0x00)
                    {
                        if (!string.IsNullOrEmpty(this.Password))
                        {
                            ep = 0x00;  //say passward is null
                        }
                    }
                    else
                    {
                        stringLength = buffer[offset];
                        password = Encoding.ASCII.GetString(buffer, offset + 1, stringLength);
                        if (!string.IsNullOrEmpty(this.Password))
                        {
                            ep = (byte)(password.Equals(this.Password) ? 0x00 : 0xFF);
                        }

                    }
                }
            }
            if (ep == 0x00)
                m_State = SocksState.Authenticated;
            byte[] returnBuffer = new byte[] { 0x01, ep };
            //send to client
            m_Session.Send(returnBuffer, 0, returnBuffer.Length);
            return (ep == 0x00);
        }

        /// <summary>
        ///Process Request
        /// </summary>
        private bool DoProtocolRequest(byte[] buffer)
        {
            string address = null;
            byte rep = 0x07;            //Does not support the command
            if (buffer.Length >= 4)
            {
                //The Address Type
                switch (buffer[3])
                {
                    case 0x01:
                        address = buffer[4] + "." + buffer[5] + "." + buffer[6] + "." + buffer[7]; //Encoding.ASCII.GetString((buffer.CloneRange<byte>(4, 4)));
                        break;
                    case 0x03:
                        //Get Domain
                        int hostLength = buffer[4];
                        address = Encoding.ASCII.GetString(buffer.CloneRange<byte>(5, hostLength));
                        break;
                    case 0x04:
                        throw new NotImplementedException();
                    default:
                        rep = 0x08; //Does not support this Type
                        break;
                }
            }

            if (address != null && rep == 0x07)
            {
                byte[] portBuffer = buffer.CloneRange<byte>(buffer.Length - 2, 2);
                Array.Reverse(portBuffer);  //Reverse port value
                //DnsEndPoint dnsEndPoint= new DnsEndPoint(ipAddress, BitConverter.ToUInt16(portBuffer, 0));
                this.RemoteEndPoint = new IPEndPoint(IPAddress.Parse(GetServerIpAddressByDomain(address)), BitConverter.ToUInt16(portBuffer, 0));
                rep = 0x00;
            }


            MemoryStream stream = new MemoryStream();
            stream.WriteByte(0x05);
            stream.WriteByte(rep);
            stream.WriteByte(0x00);
            stream.WriteByte(0x01);
            IPEndPoint localEP = m_Session.LocalEndPoint;
            byte[] localIP = localEP.Address.GetAddressBytes();
            stream.Write(localIP, 0, localIP.Length);
            byte[] localPort = BitConverter.GetBytes((ushort)IPAddress.HostToNetworkOrder(localEP.Port));
            stream.Write(localPort, 0, localPort.Length);
            byte[] returnBuffer = stream.ToArray();
            //send to client
            m_Session.Send(returnBuffer, 0, returnBuffer.Length);

            return (this.RemoteEndPoint != null);
        }

        /// <summary>
        ///  Create ProxyBridge
        /// </summary>
        private void CreateProxyBridge()
        {
            if (this.m_Session.Connected)
            {

                this.Proxy = new TcpClient();
                try
                {
                    this.Proxy.Connect(this.RemoteEndPoint);
                    if (this.Proxy.Connected)
                    {
                        this.Proxy.Client.BeginReceive(m_Session.ProxyBuffer, 0, m_Session.ProxyBuffer.Length, SocketFlags.None, this.OnProxyReceive, this.Proxy.Client);
                    }
                    else
                    {
                        m_Session.Close();
                    }
                }
                catch
                {
                    m_Session.Close();
                }


                m_State = SocksState.Connected;
            }
            else
            {
                m_Session.Close();
            }
        }

        /// <summary>
        /// When forwarding Proxyagent receives the data to the client
        /// </summary>
        /// <param name="result"></param>
        private void OnProxyReceive(IAsyncResult result)
        {
            try
            {
                Socket socket = result.AsyncState as Socket;
                SocketError error;
                int size = socket.EndReceive(result, out error);
                if (size > 0)
                {
                    //Forwarded to the client
                    m_Session.Send(m_Session.ProxyBuffer, 0, size);
                    socket.BeginReceive(m_Session.ProxyBuffer, 0, m_Session.ProxyBuffer.Length, SocketFlags.None, this.OnProxyReceive, socket);

                }
                else
                {
                    //Server already close
                    m_Session.Close();
                }
            }
            catch
            {
                m_Session.Close();
            }

        }
        
        /// <summary>
        /// very ugly way (you can implementation by youself)
        /// </summary>
        /// <param name="ServerIPOrDns"></param>
        /// <returns></returns>
        private string GetServerIpAddressByDomain(string ServerIPOrDns)
        {
            Match match = Regex.Match(ServerIPOrDns, @"\d+\.\d+\.\d+\.\d+");
            if (match.Success)
                return ServerIPOrDns;
            IPHostEntry IPH = Dns.GetHostEntry(ServerIPOrDns);
            IPAddress[] hostIPs = IPH.AddressList;
            foreach (IPAddress ip in hostIPs)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    return ip.ToString();
            }
            return "";
        }

        public int LeftBufferSize
        {
            get { throw new NotImplementedException(); }
        }



        public void Reset()
        {
            throw new NotImplementedException();
        }

        public FilterState State
        {
            get { throw new NotImplementedException(); }
        }
    }
}
