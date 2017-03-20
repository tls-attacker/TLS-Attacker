/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.unittest.helper;

import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ActionExecutorMock extends ActionExecutor {

    public ActionExecutorMock() {
    }

    @Override
    public List<ProtocolMessage> sendMessages(List<ProtocolMessage> messages) {
        return messages;
    }

    @Override
    public List<ProtocolMessage> receiveMessages(List<ProtocolMessage> messages) {
        return messages;
    }
}
