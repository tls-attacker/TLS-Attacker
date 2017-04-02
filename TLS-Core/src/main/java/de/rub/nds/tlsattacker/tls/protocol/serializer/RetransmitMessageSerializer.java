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
import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessageSerializer extends ProtocolMessageSerializer<RetransmitMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final RetransmitMessage msg;

    public RetransmitMessageSerializer(RetransmitMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        serializeCompleteResultingMessage(msg);
        return getAlreadySerialized();
    }

    private void serializeCompleteResultingMessage(RetransmitMessage msg) {
        appendBytes(msg.getCompleteResultingMessage().getValue());
        LOGGER.debug("CompleteResultingMessage: "+ Arrays.toString(msg.getCompleteResultingMessage().getValue()));
    }
}
