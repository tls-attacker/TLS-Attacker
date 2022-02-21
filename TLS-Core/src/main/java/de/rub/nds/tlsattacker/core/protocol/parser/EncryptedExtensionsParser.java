/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedExtensionsParser extends HandshakeMessageParser<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ConnectionEndType talkingConnectionEndType;

    public EncryptedExtensionsParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
        this.talkingConnectionEndType = tlsContext.getTalkingConnectionEndType();
    }

    @Override
    protected void parseHandshakeMessageContent(EncryptedExtensionsMessage msg) {
        LOGGER.debug("Parsing EncryptedExtensionsMessage");
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg, getVersion(), talkingConnectionEndType, false);
            } else {
                msg.setExtensions(new ArrayList<>());
            }
        }
    }

}
