/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

import de.rub.nds.tlsattacker.transport.nonblocking.ServerTCPNonBlockingTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpNoDelayTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.timing.TimingClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.timing.TimingServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingServerUdpTransportHandler;

public class TransportHandlerFactory {

    public static TransportHandler createTransportHandler(ConnectionEnd conEnd) {
        ConnectionEndType ourConEndType = conEnd.getConnectionEndType();
        Long timeout = new Long(conEnd.getTimeout());

        switch (conEnd.getTransportHandlerType()) {
            case TCP:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    return new ClientTcpTransportHandler(timeout, conEnd.getHostname(), conEnd.getPort());
                } else {
                    return new ServerTcpTransportHandler(timeout, conEnd.getPort());
                }
            case EAP_TLS:
                throw new UnsupportedOperationException("EAP_TLS is currently not supported");
            case UDP:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    return new ClientUdpTransportHandler(timeout, conEnd.getHostname(), conEnd.getPort());
                } else {
                    return new ServerUdpTransportHandler(timeout, conEnd.getPort());
                }
            case NON_BLOCKING_TCP:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    throw new UnsupportedOperationException("NON_BLOCKING_TCP-Transporthandler is not supported");
                } else {
                    return new ServerTCPNonBlockingTransportHandler(timeout, conEnd.getPort());
                }
            case STREAM:
                throw new UnsupportedOperationException("STREAM TransportHandler can only be created manually");
            case TCP_TIMING:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    return new TimingClientTcpTransportHandler(timeout, conEnd.getHostname(), conEnd.getPort());
                } else {
                    return new TimingServerTcpTransportHandler(timeout, conEnd.getPort());
                }
            case UDP_TIMING:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    return new TimingClientUdpTransportHandler(timeout, conEnd.getHostname(), conEnd.getPort());
                } else {
                    return new TimingServerUdpTransportHandler(timeout, conEnd.getPort());
                }
            case TCP_NO_DELAY:
                if (ourConEndType == ConnectionEndType.CLIENT) {
                    return new ClientTcpNoDelayTransportHandler(timeout, conEnd.getHostname(), conEnd.getPort());
                } else {
                    throw new UnsupportedOperationException(
                            "This transport handler type is only supported in client mode");
                }
            default:
                throw new UnsupportedOperationException("This transport handler " + "type is not supported");
        }
    }

    private TransportHandlerFactory() {

    }
}
