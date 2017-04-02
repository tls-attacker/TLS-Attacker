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
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageSerializer extends HandshakeMessageSerializer<UnknownHandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private UnknownHandshakeMessage msg;

    public UnknownHandshakeMessageSerializer(UnknownHandshakeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeData(msg);
        return getAlreadySerialized();
    }

    private void serializeData(UnknownHandshakeMessage msg) {
        appendBytes(msg.getData().getValue());
        LOGGER.debug("Data: "+ Arrays.toString(msg.getData().getValue()));
    }

}
