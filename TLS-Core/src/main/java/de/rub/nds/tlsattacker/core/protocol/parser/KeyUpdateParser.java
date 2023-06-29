/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyUpdateParser extends HandshakeMessageParser<KeyUpdateMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public KeyUpdateParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext);
    }

    @Override
    public void parse(KeyUpdateMessage msg) {
        LOGGER.debug("Parsing KeyUpdateMessage");
        parseUpdateRequest(msg);
    }

    private void parseUpdateRequest(KeyUpdateMessage msg) {
        byte requestMode = parseByteField(HandshakeByteLength.KEY_UPDATE_LENGTH);
        if (requestMode == KeyUpdateRequest.UPDATE_REQUESTED.getValue()) {
            msg.setRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);
        } else {
            msg.setRequestMode(KeyUpdateRequest.UPDATE_NOT_REQUESTED);
        }
        LOGGER.debug("KeyUpdateValue: " + msg.getRequestMode().getValue());
    }
}
