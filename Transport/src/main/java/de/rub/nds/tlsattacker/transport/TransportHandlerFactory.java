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

    private TransportHandlerFactory() {

    }

    public static TransportHandler createTransportHandler() {
	return new SimpleTransportHandler();
    }

    public static TransportHandler createTransportHandler(TransportHandlerType type, int tlsTimeout) {
	switch (type) {
	    case TCP:
		SimpleTransportHandler th = new SimpleTransportHandler();
		th.setTimeout(tlsTimeout);
		return th;
	    case EAP_TLS:
		return new EAPTLSTransportHandler();
	    case UDP:
		UDPTransportHandler udpth = new UDPTransportHandler();
		udpth.setTimeout(tlsTimeout);
		return udpth;
	    default:
		throw new UnsupportedOperationException("This transport handler " + "type is not supported");
	}
    }
}
