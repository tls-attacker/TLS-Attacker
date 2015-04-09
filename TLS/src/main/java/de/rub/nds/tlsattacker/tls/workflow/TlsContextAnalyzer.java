/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import java.lang.reflect.Field;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public final class TlsContextAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger(TlsContextAnalyzer.class);

    public enum AnalyzerResponse {
	ALERT,
	NO_ALERT,
	NO_MODIFICATION
    };

    private TlsContextAnalyzer() {

    }

    /**
     * Searches for the next protocol message sent by our peer.
     * 
     * @param tlsContext
     * @param position
     * @return
     */
    public static ProtocolMessage getNextProtocolMessageFromPeer(TlsContext tlsContext, int position) {
	ConnectionEnd peer = tlsContext.getMyConnectionEnd().getPeer();
	for (int i = position; i < tlsContext.getWorkflowTrace().getProtocolMessages().size(); i++) {
	    ProtocolMessage pm = tlsContext.getWorkflowTrace().getProtocolMessages().get(i);
	    if (peer == pm.getMessageIssuer()) {
		return pm;
	    }
	}
	return null;
    }

    /**
     * Checks whether the configured protocol message order was equal to the
     * executed protocol message order.
     * 
     * @param tlsContext
     * @return true in case the message workflow was same as the executed one or
     *         if our peer responds with a fatal alert after a protocol message
     *         modification
     */
    public static boolean checkConfiguredProtocolMessagesOrder(TlsContext tlsContext) {
	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = tlsContext.getPreconfiguredProtocolMessages();
	int min = (protocolMessages.size() < configuredProtocolMessageOrder.size()) ? protocolMessages.size()
		: configuredProtocolMessageOrder.size();
	LOGGER.info("The configured message order contains {}, there are {} protocol messages",
		configuredProtocolMessageOrder.size(), protocolMessages.size());
	for (int i = 0; i < min; i++) {
	    ProtocolMessageTypeHolder typeWorkflow = new ProtocolMessageTypeHolder(protocolMessages.get(i));
	    ProtocolMessageTypeHolder typeConfigured = configuredProtocolMessageOrder.get(i);
	    if (!typeConfigured.equals(typeWorkflow)) {
		ProtocolMessage pm = getNextProtocolMessageFromPeer(tlsContext, i - 1);
		if (pm.getProtocolMessageType() != ProtocolMessageType.ALERT) {
		    LOGGER.info("The configured message order was not equal to the executed one. Our peer has NOT "
			    + "responded with an Alert. Verify the message flow manually");
		    return false;
		} else {
		    LOGGER.info("The configured message order was not equal to the executed one, but our peer has "
			    + "responded with an Alert, everything seems to go well.");
		    return true;
		}
	    }
	}
	LOGGER.info("The configured message order was equal to the executed one");
	return true;
    }

    /**
     * Returns true in case the workflow contains a modified message and the
     * message, which is then followed by an alert issued by our peer
     * 
     * @param tlsContext
     * @return
     */
    public static AnalyzerResponse containsAlertAfterModifiedMessage(TlsContext tlsContext) {
	int position = getModifiedMessagePosition(tlsContext);
	if (position == -1) {
	    return AnalyzerResponse.NO_MODIFICATION;
	} else {
	    ProtocolMessage pm = getNextProtocolMessageFromPeer(tlsContext, position);
	    if (pm != null && pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
		return AnalyzerResponse.ALERT;
	    } else {
		return AnalyzerResponse.NO_ALERT;
	    }
	}
    }

    /**
     * Returns true in case the workflow contains a message, which has not been
     * sent by our peer and this message is followed by an alert. This test is
     * executed only in the handshake messages.
     * 
     * @param tlsContext
     * @return
     */
    public static AnalyzerResponse containsAlertAfterMissingMessage(TlsContext tlsContext) {
	int position = getMissingMessagePosition(tlsContext);
	if (position == -1) {
	    return AnalyzerResponse.NO_MODIFICATION;
	} else {
	    ProtocolMessage pm = getNextProtocolMessageFromPeer(tlsContext, position);
	    if (pm != null && pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
		return AnalyzerResponse.ALERT;
	    } else {
		return AnalyzerResponse.NO_ALERT;
	    }
	}
    }

    /**
     * Returns true in case the workflow contains a message, which has been sent
     * directly after an unexpected message.
     * 
     * @param tlsContext
     * @return
     */
    public static AnalyzerResponse containsAlertAfterUnexpectedMessage(TlsContext tlsContext) {
	int position = getUnexpectedMessagePosition(tlsContext);
	if (position == -1) {
	    return AnalyzerResponse.NO_MODIFICATION;
	} else {
	    ProtocolMessage pm = getNextProtocolMessageFromPeer(tlsContext, position);
	    if (pm != null && pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
		return AnalyzerResponse.ALERT;
	    } else {
		return AnalyzerResponse.NO_ALERT;
	    }
	}
    }

    public static boolean containsFullWorkflowWithModifiedMessage(TlsContext tlsContext) {
	return containsFullWorkflow(tlsContext) && containsModifiedMessage(tlsContext);
    }

    public static boolean containsFullWorkflowWithMissingMessage(TlsContext tlsContext) {
	return containsFullWorkflow(tlsContext) && containsMissingMessage(tlsContext);
    }

    public static boolean containsFullWorkflowWithUnexpectedMessage(TlsContext tlsContext) {
	return containsFullWorkflow(tlsContext) && containsUnexpectedMessage(tlsContext);
    }

    /**
     * The workflow was executed successfully
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsFullWorkflow(TlsContext tlsContext) {
	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = tlsContext.getPreconfiguredProtocolMessages();
	if (protocolMessages.size() != configuredProtocolMessageOrder.size()) {
	    return false;
	}
	for (int i = 0; i < protocolMessages.size(); i++) {
	    ProtocolMessage pm = protocolMessages.get(i);
	    ProtocolMessageTypeHolder typeConfigured = configuredProtocolMessageOrder.get(i);
	    if (!typeConfigured.equals(new ProtocolMessageTypeHolder(pm))) {
		return false;
	    }
	}
	return true;
    }

    /**
     * Returns true in case there is a message with a modification issued by our
     * peer
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsModifiedMessage(TlsContext tlsContext) {
	return (getModifiedMessagePosition(tlsContext) != -1);
    }

    private static int getModifiedMessagePosition(TlsContext tlsContext) {
	int position = 0;
	for (ProtocolMessage pm : tlsContext.getWorkflowTrace().getProtocolMessages()) {
	    if ((pm.getMessageIssuer() == tlsContext.getMyConnectionEnd())
		    && (containsModifiableVariableModification(pm))) {
		return position;
	    }
	    position++;
	}
	return -1;
    }

    /**
     * Returns true in case the workflow contains a message, which was
     * configured, but is not going to be sent by our peer. It considers only
     * Handshake and CCS messages
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsMissingMessage(TlsContext tlsContext) {
	return (getMissingMessagePosition(tlsContext) != -1);
    }

    private static int getMissingMessagePosition(TlsContext tlsContext) {
	int position = 0;
	for (ProtocolMessage pm : tlsContext.getWorkflowTrace().getProtocolMessages()) {
	    if ((pm.getMessageIssuer() == tlsContext.getMyConnectionEnd())
		    && (!pm.isGoingToBeSent())
		    && (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE || pm.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC)) {
		return position;
	    }
	    position++;
	}
	return -1;
    }

    /**
     * Returns true in case the workflow contains an unexpected message issued
     * by our peer
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsUnexpectedMessage(TlsContext tlsContext) {
	return (getUnexpectedMessagePosition(tlsContext) != -1);
    }

    private static int getUnexpectedMessagePosition(TlsContext tlsContext) {
	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	List<ProtocolMessageTypeHolder> configuredProtocolMessageOrder = tlsContext.getPreconfiguredProtocolMessages();
	int min = (protocolMessages.size() < configuredProtocolMessageOrder.size()) ? protocolMessages.size()
		: configuredProtocolMessageOrder.size();
	for (int i = 0; i < min; i++) {
	    ProtocolMessage pm = protocolMessages.get(i);
	    ProtocolMessageTypeHolder typeConfigured = configuredProtocolMessageOrder.get(i);
	    if ((pm.getMessageIssuer() == tlsContext.getMyConnectionEnd())
		    && (!typeConfigured.equals(new ProtocolMessageTypeHolder(pm)))) {
		return i;
	    }
	}
	return -1;
    }

    /**
     * Analyzes the modifiable variable holder and returns true in case this
     * holder contains a modification
     * 
     * @param object
     * @return
     */
    public static boolean containsModifiableVariableModification(ProtocolMessage object) {
	for (ModifiableVariableHolder holder : object.getAllModifiableVariableHolders()) {
	    for (Field f : holder.getAllModifiableVariableFields()) {
		if (containsModifiableVariableModification(holder, f)) {
		    return true;
		}
	    }
	}
	return false;
    }

    /**
     * Analyzes the modifiable variable holder and a specific field and returns
     * true in case this holder contains a modification in the given field
     * 
     * @param object
     * @param field
     * @return
     */
    private static boolean containsModifiableVariableModification(ModifiableVariableHolder object, Field field) {
	try {
	    field.setAccessible(true);
	    ModifiableVariable mv = (ModifiableVariable) field.get(object);
	    return (mv != null && mv.getModification() != null);
	} catch (IllegalAccessException | IllegalArgumentException ex) {
	    throw new ModificationException(ex.getLocalizedMessage(), ex);
	}
    }

}
