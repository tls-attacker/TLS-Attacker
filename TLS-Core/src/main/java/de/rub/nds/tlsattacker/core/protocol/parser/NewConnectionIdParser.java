/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ConnectionIdUsage;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.NewConnectionIdMessage;
import de.rub.nds.tlsattacker.core.protocol.message.connectionid.ConnectionId;
import java.io.InputStream;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdParser extends HandshakeMessageParser<NewConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(NewConnectionIdMessage message) {
        LOGGER.debug("Parsing NewConnectionId");
        parseConnectionIdsLength(message);
        parseConnectionIds(message);
        parseUsage(message);
    }

    private void parseUsage(NewConnectionIdMessage message) {
        message.setUsage(
                ConnectionIdUsage.getConnectionIdUsage(
                        parseByteField(HandshakeByteLength.NEW_CONNECTION_ID_USAGE_LENGTH)));
        LOGGER.debug("Usage: " + message.getUsage());
    }

    private void parseConnectionIds(NewConnectionIdMessage message) {
        LOGGER.debug("ConnectionIds: ");
        message.setConnectionIds(new LinkedList<>());
        for (int i = 0; i < message.getConnectionIdsLength().getValue(); ) {
            ConnectionId cid = new ConnectionId();
            cid.setLength(parseIntField(HandshakeByteLength.CONNECTION_ID_LENGTH));
            cid.setConnectionId(parseByteArrayField(cid.getLength().getValue()));
            message.getConnectionIds().add(cid);
            i += cid.getLength().getValue();

            LOGGER.debug(" - " + ArrayConverter.bytesToHexString(cid.getConnectionId().getValue()));
        }
    }

    private void parseConnectionIdsLength(NewConnectionIdMessage message) {
        message.setConnectionIdsLength(
                parseIntField(HandshakeByteLength.NEW_CONNECTION_ID_CIDS_LENGTH));
        LOGGER.debug("ConnectionIdsLength: " + message.getConnectionIdsLength().getValue());
    }
}
