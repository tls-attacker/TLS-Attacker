/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ClientKeyExchangeParser<T extends ClientKeyExchangeMessage> extends HandshakeMessageParser<ClientKeyExchangeMessage> {

    public ClientKeyExchangeParser(int startposition, byte[] array) {
        super(startposition, array, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
    }
}
