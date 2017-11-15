/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MessageActionFactory {
    public static MessageAction createAction(ConnectionEnd myConnectionEnd, ConnectionEndType sendingConnectionEndType,
            ProtocolMessage... protocolMessages) {
        return createAction(myConnectionEnd, sendingConnectionEndType, new ArrayList(Arrays.asList(protocolMessages)));
    }

    public static MessageAction createAction(ConnectionEnd myConnectionEnd, ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage> protocolMessages) {
        MessageAction action;
        if (myConnectionEnd.getConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages);
        } else {
            action = new ReceiveAction(protocolMessages);
        }
        action.setContextAlias(myConnectionEnd.getAlias());
        return action;
    }

    private MessageActionFactory() {
    }
}
