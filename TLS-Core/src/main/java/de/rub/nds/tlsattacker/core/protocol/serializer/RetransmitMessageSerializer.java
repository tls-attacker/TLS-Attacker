/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessageSerializer extends ProtocolMessageSerializer<RetransmitMessage> {

    private final RetransmitMessage msg;

    /**
     * Constructor for the RetransmitMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public RetransmitMessageSerializer(RetransmitMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        writeCompleteResultingMessage(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CompleteResultingMessage of the RetransmitMessage into the
     * final byte[]
     */
    private void writeCompleteResultingMessage(RetransmitMessage msg) {
        appendBytes(msg.getCompleteResultingMessage().getValue());
        LOGGER.debug("CompleteResultingMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }
}
