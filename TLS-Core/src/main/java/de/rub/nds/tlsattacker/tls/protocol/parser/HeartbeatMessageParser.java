/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HeartbeatByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatMessageParser extends Parser<HeartbeatMessage>{

    public HeartbeatMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public HeartbeatMessage parse() {
        HeartbeatMessage message = new HeartbeatMessage();
        message.setHeartbeatMessageType(parseByteField(HeartbeatByteLength.TYPE));
        message.setPayloadLength(parseIntField(HeartbeatByteLength.PAYLOAD_LENGTH));
        message.setPayload(parseByteArrayField(message.getPayloadLength().getValue()));
        message.setPadding(parseByteArrayField(getBytesLeft()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
    
}
