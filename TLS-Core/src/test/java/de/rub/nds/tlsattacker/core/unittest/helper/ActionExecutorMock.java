/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.unittest.helper;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ActionExecutorMock extends ActionExecutor {

    public ActionExecutorMock() {
    }

    @Override
    public MessageActionResult sendMessages(List<ProtocolMessage> messages, List<AbstractRecord> records) {
        return new MessageActionResult(records, messages);
    }

    @Override
    public MessageActionResult receiveMessages(List<ProtocolMessage> messages) {
        return new MessageActionResult(new LinkedList<AbstractRecord>(), messages);
    }
}
