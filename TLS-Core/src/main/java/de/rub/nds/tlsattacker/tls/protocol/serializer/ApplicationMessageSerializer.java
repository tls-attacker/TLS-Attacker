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
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessageSerializer extends ProtocolMessageSerializer<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final ApplicationMessage msg;

    public ApplicationMessageSerializer(ApplicationMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        serializeData(msg);
        appendBytes(msg.getData().getValue());
        return getAlreadySerialized();
    }

    private void serializeData(ApplicationMessage msg) {
        appendBytes(msg.getData().getValue());
        LOGGER.debug("Data: "+ Arrays.toString(msg.getData().getValue()));
    }

}
