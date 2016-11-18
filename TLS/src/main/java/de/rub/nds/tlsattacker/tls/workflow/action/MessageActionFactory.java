/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageActionFactory {
    public static MessageAction createAction(ConnectionEnd myConnectionEnd, ConnectionEnd sendingConnectionEnd,
            ProtocolMessage... protocolMessages) {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (ProtocolMessage tempMessage : protocolMessages) {
            messages.add(tempMessage);
        }
        if (myConnectionEnd == sendingConnectionEnd) {
            return new SendAction(messages);
        } else {
            return new ReceiveAction(messages);
        }

    }

    public static MessageAction createAction(ConnectionEnd myConnectionEnd, ConnectionEnd sendingConnectionEnd,
            List<ProtocolMessage> protocolMessages) {
        if (myConnectionEnd == sendingConnectionEnd) {
            return new SendAction(protocolMessages);
        } else {
            return new ReceiveAction(protocolMessages);
        }

    }
}
