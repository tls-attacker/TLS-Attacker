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

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TransportHandlerFactory {

    public static TransportHandler createTransportHandler(String hostname, int port, ConnectionEndType end,
            int timeout, TransportHandlerType type) {
        switch (type) {
            case TCP:
                if (end == ConnectionEndType.CLIENT) {
                    return new ClientTcpTransportHandler(timeout, hostname, port);
                } else {
                    return new ServerTcpTransportHandler(timeout, port);
                }
            case EAP_TLS:
                throw new UnsupportedOperationException("EAP_TLS is currently not supported");
            case UDP:
                if (end == ConnectionEndType.CLIENT) {
                    return new ClientUdpTransportHandler(timeout, hostname, port);
                } else {
                    return new ServerUdpTransportHandler(timeout, port);
                }
            case NON_BLOCKING_TCP:
                if (end == ConnectionEndType.CLIENT) {
                    throw new UnsupportedOperationException("NON_BLOCKING_TCP-Transporthandler is not supported");
                } else {
                    return new ServerTCPNonBlockingTransportHandler(timeout, port);
                }
            case STREAM:
                throw new UnsupportedOperationException("STREAM TransportHandler can only be created manually");
            case TCP_TIMING:
                if (end == ConnectionEndType.CLIENT) {
                    return new TimingClientTcpTransportHandler(timeout, hostname, port);
                } else {
                    return new TimingServerTcpTransportHandler(timeout, port);
                }
            case UDP_TIMING:
                if (end == ConnectionEndType.CLIENT) {
                    return new TimingClientUdpTransportHandler(timeout, hostname, port);
                } else {
                    return new TimingServerUdpTransportHandler(timeout, port);
                }
            case TCP_NO_DELAY:
                if (end == ConnectionEndType.CLIENT) {
                    return new ClientTcpNoDelayTransportHandler(timeout, hostname, port);
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
