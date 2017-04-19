/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TransportHandlerFactory {

    public static TransportHandler createTransportHandler(String hostname, int port, ConnectionEnd end, int tlsTimeout,
            int socketTimeout, TransportHandlerType type) {
        switch (type) {
            case TCP:
                return new SimpleTransportHandler(hostname, port, end, socketTimeout, tlsTimeout);
            case EAP_TLS:
                throw new UnsupportedOperationException("EAP_TLS is currently not supported");
            case UDP:
                return new UDPTransportHandler(hostname, port, end, tlsTimeout);
            default:
                throw new UnsupportedOperationException("This transport handler " + "type is not supported");
        }
    }

    private TransportHandlerFactory() {

    }
}
