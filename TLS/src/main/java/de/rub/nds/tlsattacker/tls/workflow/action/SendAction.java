/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class SendAction extends MessageAction {

    public SendAction() {
	super(new LinkedList<ProtocolMessage>());
    }

    public SendAction(List<ProtocolMessage> messages) {
	super(messages);
    }

    public SendAction(ProtocolMessage message) {
	super(new LinkedList<ProtocolMessage>());
	configuredMessages.add(message);
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) {
	if (executed) {
	    throw new WorkflowExecutionException("Action already executed!");
	}
	tlsContext.setTalkingConnectionEnd(tlsContext.getMyConnectionEnd());
	ensureMyLastProtocolMessagesHaveRecords(configuredMessages); // I dont
								     // think we
								     // want the
								     // workflowExecutor
								     // to
								     // modify
								     // the
								     // workflowtrace,
								     // it
								     // should
								     // simply
								     // execute
								     // it
	actualMessages = executor.sendMessages(tlsContext, configuredMessages);
	executed = true;

    }

    private void ensureMyLastProtocolMessagesHaveRecords(List<ProtocolMessage> protocolMessages) {
	for (int pmPointer = 0; pmPointer < protocolMessages.size(); pmPointer++) {
	    ProtocolMessage pm = protocolMessages.get(pmPointer);
	    if (handlingMyLastProtocolMessageWithContentType(protocolMessages, pmPointer)) {
		if (pm.getRecords() == null || pm.getRecords().isEmpty()) {
		    pm.addRecord(new Record());
		}
	    }
	}
    }

    /**
     * In case we are handling last protocol message, this protocol message has
     * to be flushed out. The reasons for flushing out the message can be
     * following: 1) it is the last protocol message 2) the next protocol
     * message should come from the different peer 3) the next protocol message
     * has a different content type
     * 
     * @param protocolMessages
     * @param pointer
     * @return
     */
    private boolean handlingMyLastProtocolMessageWithContentType(List<ProtocolMessage> protocolMessages, int pointer) {
	ProtocolMessage currentProtocolMessage = protocolMessages.get(pointer);
	return ((protocolMessages.size() == (pointer + 1)) || currentProtocolMessage.getProtocolMessageType() != (protocolMessages
		.get(pointer + 1).getProtocolMessageType()));
    }

    private static final Logger LOG = Logger.getLogger(SendAction.class.getName());

}
