/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageActionFactory {
    public static MessageAction createAction(AliasedConnection connection, ConnectionEndType sendingConnectionEndType,
            ProtocolMessage... protocolMessages) {
        return createAction(connection, sendingConnectionEndType, Arrays.asList(protocolMessages));
    }

    public static MessageAction createAction(AliasedConnection connection, ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage> protocolMessages) {
        MessageAction action;
        if (connection.getLocalConnectionEndType() == sendingConnectionEnd) {
            action = new SendAction(protocolMessages);
        } else {
            action = new ReceiveAction(protocolMessages);
        }
        action.setConnectionAlias(connection.getAlias());
        return action;
    }

    private MessageActionFactory() {
    }
}
