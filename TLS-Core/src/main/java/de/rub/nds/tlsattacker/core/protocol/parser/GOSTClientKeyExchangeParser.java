/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;

public class GOSTClientKeyExchangeParser extends ClientKeyExchangeParser<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(GOSTClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing GOSTClientKeyExchangeMessage");
        msg.setKeyTransportBlob(parseByteArrayField(msg.getLength().getValue()));
    }

    @Override
    protected GOSTClientKeyExchangeMessage createHandshakeMessage() {
        return new GOSTClientKeyExchangeMessage();
    }

}
