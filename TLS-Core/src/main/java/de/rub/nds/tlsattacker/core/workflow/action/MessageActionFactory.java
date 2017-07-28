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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageActionFactory {
    public static MessageAction createAction(ConnectionEndType myConnectionEndType,
            ConnectionEndType sendingConnectionEndType, ProtocolMessage... protocolMessages) {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.addAll(Arrays.asList(protocolMessages));
        if (myConnectionEndType == sendingConnectionEndType) {
            return new SendAction(messages);
        } else {
            return new ConfiguredReceiveAction(messages);
        }

    }

    public static MessageAction createAction(ConnectionEndType myConnectionEnd, ConnectionEndType sendingConnectionEnd,
            List<ProtocolMessage> protocolMessages) {
        if (myConnectionEnd == sendingConnectionEnd) {
            return new SendAction(protocolMessages);
        } else {
            return new ConfiguredReceiveAction(protocolMessages);
        }

    }

    private MessageActionFactory() {
    }
}
