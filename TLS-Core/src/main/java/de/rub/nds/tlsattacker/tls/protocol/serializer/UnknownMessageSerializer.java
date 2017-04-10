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
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessageSerializer extends ProtocolMessageSerializer<UnknownMessage> {

    private UnknownMessage msg;

    /**
     * Constructor for the UnknownMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public UnknownMessageSerializer(UnknownMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        writeCompleteResultinMessage(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CompleteResultingMessage of the UnknownMessage into the final
     * byte[]
     */
    private void writeCompleteResultinMessage(UnknownMessage msg) {
        appendBytes(msg.getCompleteResultingMessage().getValue());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }

}
