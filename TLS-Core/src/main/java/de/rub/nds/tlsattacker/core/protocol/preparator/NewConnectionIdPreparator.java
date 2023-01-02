/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ConnectionIdUsage;
import de.rub.nds.tlsattacker.core.protocol.message.NewConnectionIdMessage;
import de.rub.nds.tlsattacker.core.protocol.message.connectionid.ConnectionId;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdPreparator extends HandshakeMessagePreparator<NewConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdPreparator(Chooser chooser, NewConnectionIdMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        message.setUsage(ConnectionIdUsage.CID_SPARE);
        int numCids = chooser.getNumberOfRequestedConnectionIds();
        LOGGER.debug("Preparing NewConnectionId with " + numCids + "CIDs");
        message.setConnectionIds(new LinkedList<>());
        int length = 0;
        for (int i = 0; i < numCids; i++) {
            ConnectionId cid = new ConnectionId(chooser.getConfig().getDefaultConnectionId());
            message.getConnectionIds().add(cid);
            length += cid.getLength().getValue();
        }
        message.setConnectionIdsLength(length);
    }
}
