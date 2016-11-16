/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ModificationException;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageTypeHolder;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
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
    public static ProtocolMessage getNextReceiveProtocolMessage(TlsContext tlsContext, int position) {
        ConnectionEnd peer = tlsContext.getMyConnectionEnd().getPeer();
        for (int i = position; i < tlsContext.getWorkflowTrace().getAllConfiguredReceivingMessages().size(); i++) {
            ProtocolMessage pm = tlsContext.getWorkflowTrace().getAllConfiguredReceivingMessages().get(i);
            return pm;
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
        List<ProtocolMessage> configuredProtocolMessageOrder = tlsContext.getWorkflowTrace()
                .getAllConfiguredReceivingMessages();
        List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getAllActuallyReceivedMessages();
        int min = (protocolMessages.size() < configuredProtocolMessageOrder.size()) ? protocolMessages.size()
                : configuredProtocolMessageOrder.size();
        LOGGER.info("The configured message order contains {}, there are {} protocol messages",
                configuredProtocolMessageOrder.size(), protocolMessages.size());
        for (int i = 0; i < min; i++) {
            ProtocolMessageTypeHolder typeWorkflow = new ProtocolMessageTypeHolder(protocolMessages.get(i));
            ProtocolMessageTypeHolder typeConfigured = new ProtocolMessageTypeHolder(configuredProtocolMessageOrder
                    .get(i).getProtocolMessageType());
            if (!typeConfigured.equals(typeWorkflow)) {
                ProtocolMessage pm = getNextReceiveProtocolMessage(tlsContext, i - 1);
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
    // Does not analyze the actually received
    public static AnalyzerResponse containsAlertAfterModifiedMessage(TlsContext tlsContext) {
        int position = getModifiedMessagePosition(tlsContext);
        if (position == -1) {
            return AnalyzerResponse.NO_MODIFICATION;
        } else {
            ProtocolMessage pm = getNextReceiveProtocolMessage(tlsContext, position);
            if (pm != null && pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
                return AnalyzerResponse.ALERT;
            } else {
                return AnalyzerResponse.NO_ALERT;
            }
        }
    }

    //
    // /**
    // * //TODO Deprecated
    // * Returns true in case the workflow contains a message, which has not
    // been
    // * sent by our peer and this message is followed by an alert. This test is
    // * executed only in the handshake messages.
    // *
    // * @param tlsContext
    // * @return
    // */
    // public static AnalyzerResponse
    // containsAlertAfterMissingMessage(TlsContext tlsContext)
    // {
    // int position = getMissingMessagePosition(tlsContext);
    // if (position == -1)
    // {
    // return AnalyzerResponse.NO_MODIFICATION;
    // }
    // else
    // {
    // ProtocolMessage pm = getNextReceiveProtocolMessage(tlsContext, position);
    // if (pm != null && pm.getProtocolMessageType() ==
    // ProtocolMessageType.ALERT)
    // {
    // return AnalyzerResponse.ALERT;
    // }
    // else
    // {
    // return AnalyzerResponse.NO_ALERT;
    // }
    // }
    // }
    //
    // /**
    // * Returns true in case the workflow contains a message, which has been
    // sent
    // * directly after an unexpected message.
    // *
    // * @param tlsContext
    // * @return
    // */
    // public static AnalyzerResponse
    // containsAlertAfterUnexpectedMessage(TlsContext tlsContext)
    // {
    // int position = getUnexpectedMessagePosition(tlsContext);
    // if (position == -1)
    // {
    // return AnalyzerResponse.NO_MODIFICATION;
    // }
    // else
    // {
    // ProtocolMessage pm = getNextReceiveProtocolMessage(tlsContext, position);
    // if (pm != null && pm.getProtocolMessageType() ==
    // ProtocolMessageType.ALERT)
    // {
    // return AnalyzerResponse.ALERT;
    // }
    // else
    // {
    // return AnalyzerResponse.NO_ALERT;
    // }
    // }
    // }

    public static boolean containsFullWorkflowWithModifiedMessage(TlsContext tlsContext) {
        return containsFullWorkflow(tlsContext) && containsModifiedMessage(tlsContext);
    }

    public static boolean containsFullWorkflowWithMissingMessage(TlsContext tlsContext) {
        return containsFullWorkflow(tlsContext) && containsMissingMessage(tlsContext);
    }

    public static boolean receivedFinishedWithModifiedHandshake(TlsContext tlsContext) {
        return receivedFinishedMessage(tlsContext) && containsModifiedHandshake(tlsContext);
    }

    /**
     * The workflow was executed successfully
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsFullWorkflow(TlsContext tlsContext) {
        List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getAllConfiguredReceivingMessages();
        List<ProtocolMessage> actuallyReveivedMessages = tlsContext.getWorkflowTrace().getAllActuallyReceivedMessages();
        if (protocolMessages.size() != actuallyReveivedMessages.size()) {
            return false;
        }
        for (int i = 0; i < protocolMessages.size(); i++) {
            ProtocolMessage pm = protocolMessages.get(i);
            ProtocolMessageTypeHolder typeConfigured = new ProtocolMessageTypeHolder(actuallyReveivedMessages.get(i));
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
        for (ProtocolMessage pm : tlsContext.getWorkflowTrace().getAllConfiguredMessages()) {
            if (containsModifiableVariableModification(pm)) {
                return position;
            }
            position++;
        }
        return -1;
    }

    /**
     * Returns true in case there is a modification in the handshake
     * 
     * @param tlsContext
     * @return
     */
    public static boolean containsModifiedHandshake(TlsContext tlsContext) {
        int unexpected = getMessageActionPositionWithUnexpectedMessage(tlsContext.getWorkflowTrace());
        int finished = getReceiveFinishedMessagePosition(tlsContext);
        if (unexpected != -1) {
            if (finished == -1) {
                return true;
            } else {
                return unexpected < finished;
            }
        }
        return false;
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
        for (ProtocolMessage pm : tlsContext.getWorkflowTrace().getAllConfiguredMessages()) {
            if (!pm.isGoingToBeSent()
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
    public static boolean containsUnexpectedMessage(WorkflowTrace trace) {
        return (getMessageActionPositionWithUnexpectedMessage(trace) != -1);
    }

    private static int getMessageActionPositionWithUnexpectedMessage(WorkflowTrace trace) {
        List<ReceiveAction> receiveActions = trace.getReceiveActions();
        int counter = 0;
        for (ReceiveAction action : receiveActions) {
            if (action.getActualMessages().size() != action.getConfiguredMessages().size()) {
                return counter;
            }
            // Check if Messages are the same
            for (int i = 0; i < action.getActualMessages().size(); i++) {
                ProtocolMessage receivedMessage = action.getActualMessages().get(i);
                ProtocolMessage expectedMessage = action.getConfiguredMessages().get(i);
                if (receivedMessage.getProtocolMessageType() == expectedMessage.getProtocolMessageType()) {
                    if (!receivedMessage.getClass().equals(expectedMessage.getClass())) {
                        return counter;
                    }
                } else {
                    return counter;
                }

            }
            counter++;
        }
        return -1;
    }

    /**
     * Returns true in case the workflow a server Finished Message
     * 
     * @param tlsContext
     * @return
     */
    public static boolean receivedFinishedMessage(TlsContext tlsContext) {
        return (getReceiveFinishedMessagePosition(tlsContext) != -1);
    }

    private static int getReceiveFinishedMessagePosition(TlsContext tlsContext) {
        List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getAllConfiguredReceivingMessages();
        for (int i = 0; i < protocolMessages.size(); i++) {
            ProtocolMessage pm = protocolMessages.get(i);
            if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
                HandshakeMessage hm = (HandshakeMessage) pm;
                if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {
                    return i;
                }
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
            return (mv != null && mv.getModification() != null && mv.isOriginalValueModified());
        } catch (IllegalAccessException | IllegalArgumentException ex) {
            throw new ModificationException(ex.getLocalizedMessage(), ex);
        }
    }

}
