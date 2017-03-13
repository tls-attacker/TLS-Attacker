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
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageParser extends HandshakeMessageParser<UnknownHandshakeMessage> {

    static final Logger LOGGER = LogManager.getLogger(UnknownHandshakeMessage.class);

    public UnknownHandshakeMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.UNKNOWN, version);
    }

    @Override
    protected void parseHandshakeMessageContent(UnknownHandshakeMessage msg) {
        msg.setData(parseByteArrayField(msg.getLength().getValue()));
        LOGGER.warn("Parsed UnknownHandshake Message: "
                + ArrayConverter.bytesToHexString(msg.getData().getValue(), false));

    }

    @Override
    protected UnknownHandshakeMessage createHandshakeMessage() {
        return new UnknownHandshakeMessage();
    }
}
