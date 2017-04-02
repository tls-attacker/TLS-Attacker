/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecSerializer extends ProtocolMessageSerializer<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private ChangeCipherSpecMessage msg;

    public ChangeCipherSpecSerializer(ChangeCipherSpecMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        serializeCcsProtocolType(msg);
        return getAlreadySerialized();
    }

    private void serializeCcsProtocolType(ChangeCipherSpecMessage msg) {
        appendByte(msg.getCcsProtocolType().getValue());
        LOGGER.debug("CcsProtocolType: "+ msg.getCcsProtocolType().getValue());
    }

}
