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
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedMessageParser extends HandshakeMessageParser<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");
    
    public FinishedMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.FINISHED, version);
    }

    @Override
    protected void parseHandshakeMessageContent(FinishedMessage msg) {
        msg.setVerifyData(parseByteArrayField(msg.getLength().getValue()));
    }

    @Override
    protected FinishedMessage createHandshakeMessage() {
        return new FinishedMessage();
    }

}
