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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 */
public abstract class ClientKeyExchangeParser<T extends ClientKeyExchangeMessage> extends HandshakeMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");
    
    public ClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, HandshakeMessageType.CLIENT_KEY_EXCHANGE, version);
    }
}
