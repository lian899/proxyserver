using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SuperSocket.SocketBase.Protocol;
using SuperSocket.Common;

namespace SuperSocket.ProxyServer
{
    public class SocksProxyServer : ProxyAppServer
    {
        internal string UserName { get; private set; }
        internal string Password { get; private set; }

        public SocksProxyServer()
            : base(new SocksProxyReceiveFilterFactory())
        {

        }

        protected override bool Setup(SocketBase.Config.IRootConfig rootConfig, SocketBase.Config.IServerConfig config)
        {
            UserName = config.Options.GetValue("userName");
            Password = config.Options.GetValue("password");
            return base.Setup(rootConfig, config);
        }

    }
}
