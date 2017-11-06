/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.exceptions;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;

/**
 * Invalid message type exception (thrown when unexpected TLS message appears
 * during the TLS workflow)
 */
public class InvalidMessageTypeException extends RuntimeException {

    public InvalidMessageTypeException() {
        super();
    }

    public InvalidMessageTypeException(String message) {
        super(message);
    }

    public InvalidMessageTypeException(ProtocolMessageType protocolMessageType) {
        super("This is not a " + protocolMessageType + " message");
    }

    public InvalidMessageTypeException(HandshakeMessageType handshakeMessageType) {
        super("This is not a " + handshakeMessageType + " message");
    }
}
