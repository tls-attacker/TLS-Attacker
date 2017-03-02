/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerKeyExchangeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ServerKeyExchangeParser<T extends ServerKeyExchangeMessage> extends
        HandshakeMessageParser<T> {

    public ServerKeyExchangeParser(int pointer, byte[] array, HandshakeMessageType expectedType) {
        super(pointer, array, expectedType);
    }
}
