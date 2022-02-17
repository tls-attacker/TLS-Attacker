/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.transport.tcp.ClientTcpNoDelayTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.fragmentation.ClientTcpFragmentationTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.fragmentation.ServerTcpFragmentationTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.proxy.TimingProxyClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.timing.TimingClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.timing.TimingServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.proxy.ProxyClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingServerUdpTransportHandler;

public class TransportHandlerFactory {

    public static TransportHandler createTransportHandler(Connection con) {
        ConnectionEndType localConEndType = con.getLocalConnectionEndType();

        switch (con.getTransportHandlerType()) {
            case TCP:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new ClientTcpTransportHandler(con);
                } else {
                    return new ServerTcpTransportHandler(con);
                }
            case EAP_TLS:
                throw new UnsupportedOperationException("EAP_TLS is currently not supported");
            case UDP:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new ClientUdpTransportHandler(con);
                } else {
                    return new ServerUdpTransportHandler(con);
                }
            case STREAM:
                throw new UnsupportedOperationException("STREAM TransportHandler can only be created manually");
            case TCP_TIMING:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new TimingClientTcpTransportHandler(con);
                } else {
                    return new TimingServerTcpTransportHandler(con);
                }
            case UDP_TIMING:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new TimingClientUdpTransportHandler(con);
                } else {
                    return new TimingServerUdpTransportHandler(con);
                }
            case UDP_PROXY:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new ProxyClientUdpTransportHandler(con);
                } else {
                    throw new UnsupportedOperationException("UDP_PROXY for server sockets is currently not supported");
                }
            case TCP_PROXY_TIMING:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new TimingProxyClientTcpTransportHandler(con);
                } else {
                    throw new UnsupportedOperationException(
                        "TCP_PROXY_TIMING for server sockets is currently not supported");
                }
            case TCP_NO_DELAY:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new ClientTcpNoDelayTransportHandler(con);
                } else {
                    throw new UnsupportedOperationException(
                        "This Transporthandler type is only supported in client mode");
                }
            case TCP_FRAGMENTATION:
                if (localConEndType == ConnectionEndType.CLIENT) {
                    return new ClientTcpFragmentationTransportHandler(con);
                } else {
                    return new ServerTcpFragmentationTransportHandler(con);
                }
            default:
                throw new UnsupportedOperationException(
                    "Transport handler " + con.getTransportHandlerType() + " is not supported");
        }
    }

    private TransportHandlerFactory() {

    }
}
