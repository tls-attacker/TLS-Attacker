/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.attacks.ths;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.MessageBytesCollector;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Triple Handshake Attack Workflowexecutor for synchronizing the
 * PremasterSecret
 * 
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeWorkflowExecutor extends GenericWorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(TripleHandshakeWorkflowExecutor.class);

    /**
     * indicates if workflow executed as client
     */
    protected boolean client = false;

    /**
     * indicates if Key-Exchange is DHE
     */
    protected boolean dheKeyEx = false;

    protected final TripleHandshakeSharedContext sharedContext;

    MessageBytesCollector messageBytesCollector;

    /**
     * indicates where the Threads have to be synchronized
     */
    private int syncA, syncB;

    public TripleHandshakeWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext,
	    TripleHandshakeSharedContext sharedContext) {
	super(transportHandler, tlsContext);
	this.sharedContext = sharedContext;
	this.recordHandler = new RecordHandler(tlsContext);
	tlsContext.setRecordHandler(recordHandler);
	this.messageBytesCollector = new MessageBytesCollector();
	this.workflowContext = new WorkflowContext();
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
	if (executed) {
	    throw new IllegalStateException("The workflow has already been" + " executed. Create a new Workflow.");
	}
	executed = true;

	tlsContext.setTHSAttack(true);

	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT) {
	    client = true;
	    try {
		sharedContext.lock();
	    } catch (InterruptedException e) {
		throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	    }
	}

	CipherSuite cs = tlsContext.getSelectedCipherSuite();
	switch (KeyExchangeAlgorithm.getKeyExchangeAlgorithm(cs)) {
	    case RSA:
		if (client) {
		    syncA = 0;
		    syncB = 4;
		} else {
		    syncA = 1;
		    syncB = 7;
		}
		break;
	    case DHE_RSA:
		if (client) {
		    syncA = 0;
		    syncB = 5;
		} else {
		    syncA = 1;
		    syncB = 8;
		}
		dheKeyEx = true;
		break;
	    default:
		throw new UnsupportedOperationException("This configuration is not supported yet"
			+ "or the Triple Handshake Attack ist not possible with this key exchange algorithm");
	}

	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	ensureMyLastProtocolMessagesHaveRecords(protocolMessages);
	try {
	    while (workflowContext.getProtocolMessagePointer() < protocolMessages.size()
		    && workflowContext.isProceedWorkflow()) {
		ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
		    if (workflowContext.getProtocolMessagePointer() == syncA
			    | workflowContext.getProtocolMessagePointer() == syncB) {
			synchronizeWorkflowsBeforePrepare(workflowContext.getProtocolMessagePointer());
		    }
		    handleMyProtocolMessage(protocolMessages);
		} else {
		    handleProtocolMessagesFromPeer(protocolMessages);
		    if (workflowContext.getProtocolMessagePointer() == syncA
			    | workflowContext.getProtocolMessagePointer() == syncB) {
			synchronizeWorkflowsAfterParse(workflowContext.getProtocolMessagePointer());
		    }
		}
	    }
	} catch (WorkflowExecutionException | CryptoException | IOException e) {
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	} finally {
	    // remove all unused protocol messages
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	}
	tlsContext.setTHSAttack(false);
    }

    private void synchronizeWorkflowsBeforePrepare(int syncPoint) {
	if (client) {
	    if (syncPoint == syncA) {
		tlsContext.setClientRandom(sharedContext.getClientRandom());
	    }
	    if (syncPoint == syncB && !dheKeyEx) {
		tlsContext.setPreMasterSecret(sharedContext.getPreMasterSecret());
	    }
	}

	else {
	    if (syncPoint == syncA) {
		tlsContext.setServerRandom(sharedContext.getServerRandom());
		tlsContext.setSessionID(sharedContext.getSessionID());
		if (dheKeyEx) {
		    tlsContext.setServerDHParameters(sharedContext.getServerDHParameters());
		}
	    }
	}
    }

    private void synchronizeWorkflowsAfterParse(int syncPoint) {
	if (client) {
	    if (syncPoint == syncB) {
		sharedContext.setServerRandom(tlsContext.getServerRandom());
		sharedContext.setSessionID(tlsContext.getSessionID());
		if (dheKeyEx) {
		    sharedContext.setServerDHParameters(tlsContext.getServerDHParameters());
		}
		try {
		    sharedContext.unlockAndWait();
		} catch (InterruptedException e) {
		    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
		}
	    }
	}

	else {
	    if (syncPoint == syncA) {
		sharedContext.setClientRandom(tlsContext.getClientRandom());
		try {
		    sharedContext.unlockAndWait();
		} catch (InterruptedException e) {
		    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
		}
	    }
	    if (syncPoint == syncB) {
		if (!dheKeyEx) {
		    sharedContext.setPreMasterSecret(tlsContext.getPreMasterSecret());
		}
		try {
		    sharedContext.unlock();
		} catch (InterruptedException e) {
		    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
		}
	    }
	}
    }

    private void handleMyProtocolMessage(List<ProtocolMessage> protocolMessages) throws IOException {
	ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	prepareMyProtocolMessageBytes(pm);
	prepareMyRecordsIfNeeded(pm);
	sendDataIfMyLastMessage(protocolMessages);
	workflowContext.incrementProtocolMessagePointer();
    }

    /**
     * 
     * @param pmh
     */
    private void handleIncomingAlert(ProtocolMessageHandler pmh) {
	if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
	    am.setMessageIssuer(ConnectionEnd.SERVER);
	    if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
		LOGGER.debug("The workflow execution is stopped because of a FATAL error");
		workflowContext.setProceedWorkflow(false);
	    }
	}
    }

    /**
     * 
     * @param protocolMessages
     * @param pmh
     */
    private void identifyCorrectProtocolMessage(List<ProtocolMessage> protocolMessages, ProtocolMessageHandler pmh) {
	ProtocolMessage pm = null;
	if (workflowContext.getProtocolMessagePointer() < protocolMessages.size()) {
	    pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	}
	if (pm != null && pmh.isCorrectProtocolMessage(pm)) {
	    pmh.setProtocolMessage(pm);
	} else {
	    // the configured message is not the same as
	    // the message being parsed, we clean the
	    // next protocol messages
	    LOGGER.debug("The configured protocol message is not equal to "
		    + "the message being parsed or the message was not found.");
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	    pmh.initializeProtocolMessage();
	    pm = pmh.getProtocolMessage();
	    protocolMessages.add(pm);
	}
    }
}
