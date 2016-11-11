/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ReceiveAction extends MessageAction {

    public ReceiveAction() {
        super(new LinkedList<ProtocolMessage>());
    }

    public ReceiveAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public ReceiveAction(ProtocolMessage message) {
        super(new LinkedList<ProtocolMessage>());
        configuredMessages.add(message);
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) {
        if (executed) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        tlsContext.setTalkingConnectionEnd(tlsContext.getMyConnectionPeer());
        actualMessages = executor.receiveMessages(configuredMessages);
        executed = true;
    }

    private static final Logger LOG = Logger.getLogger(ReceiveAction.class.getName());

}
