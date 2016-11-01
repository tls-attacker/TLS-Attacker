/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.FatalAertMessageException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.workflow.RenegotiationWorkflowConfiguration;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlTransient;

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
	actualMessages = executor.receiveMessages(tlsContext, configuredMessages);
	executed = true;
    }

    private static final Logger LOG = Logger.getLogger(ReceiveAction.class.getName());

}
