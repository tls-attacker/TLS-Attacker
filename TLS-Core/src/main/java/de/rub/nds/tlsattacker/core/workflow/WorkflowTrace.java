/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A wrapper class over a list of protocol expectedMessages. */
@XmlRootElement(name = "workflowTrace")
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Copy a workflow trace.
     *
     * <p>TODO: This should be replaced by a better copy method. Using serialization is slow and
     * needs some additional "tweaks", i.e. we have to manually restore important fields marked as
     * XmlTransient. This problem arises because the classes are configured for nice JAXB output,
     * and not for copying/storing full objects.
     *
     * @param orig the original WorkflowTrace object to copy
     * @return a copy of the original WorkflowTrace
     */
    public static WorkflowTrace copy(WorkflowTrace orig) {
        WorkflowTrace copy = null;

        List<TlsAction> origActions = orig.getTlsActions();

        try {
            String origTraceStr = WorkflowTraceSerializer.write(orig);
            InputStream is =
                    new ByteArrayInputStream(origTraceStr.getBytes(StandardCharsets.UTF_8.name()));
            copy = WorkflowTraceSerializer.insecureRead(is);
        } catch (JAXBException | IOException | XMLStreamException ex) {
            throw new ConfigurationException("Could not copy workflow trace: " + ex);
        }

        List<TlsAction> copiedActions = copy.getTlsActions();
        for (int i = 0; i < origActions.size(); i++) {
            copiedActions
                    .get(i)
                    .setSingleConnectionWorkflow(origActions.get(i).isSingleConnectionWorkflow());
        }

        return copy;
    }

    @XmlElements(
            value = {
                @XmlElement(type = AliasedConnection.class, name = "AliasedConnection"),
                @XmlElement(type = InboundConnection.class, name = "InboundConnection"),
                @XmlElement(type = OutboundConnection.class, name = "OutboundConnection")
            })
    private List<AliasedConnection> connections = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElements(
            value = {
                @XmlElement(type = ActivateDecryptionAction.class, name = "ActivateDecryption"),
                @XmlElement(type = ActivateEncryptionAction.class, name = "ActivateEncryption"),
                @XmlElement(
                        type = ApplyBufferedMessagesAction.class,
                        name = "ApplyBufferedMessages"),
                @XmlElement(
                        type = BufferedGenericReceiveAction.class,
                        name = "BufferedGenericReceive"),
                @XmlElement(type = BufferedSendAction.class, name = "BufferedSend"),
                @XmlElement(type = ChangeCipherSuiteAction.class, name = "ChangeCipherSuite"),
                @XmlElement(type = ChangeClientRandomAction.class, name = "ChangeClientRandom"),
                @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompression"),
                @XmlElement(type = ChangeContextValueAction.class, name = "ChangeContextValue"),
                @XmlElement(type = ChangeMasterSecretAction.class, name = "ChangeMasterSecret"),
                @XmlElement(
                        type = ChangePreMasterSecretAction.class,
                        name = "ChangePreMasterSecret"),
                @XmlElement(
                        type = ChangeServerRsaParametersAction.class,
                        name = "ChangeServerRsaParameters"),
                @XmlElement(
                        type = ChangeDefaultPreMasterSecretAction.class,
                        name = "ChangeDefaultPreMasterSecret"),
                @XmlElement(
                        type = ChangeProtocolVersionAction.class,
                        name = "ChangeProtocolVersion"),
                @XmlElement(type = ChangeServerRandomAction.class, name = "ChangeServerRandom"),
                @XmlElement(
                        type = ChangeConnectionTimeoutAction.class,
                        name = "ChangeConnectionTimeout"),
                @XmlElement(type = ChangeReadEpochAction.class, name = "ChangeReadEpoch"),
                @XmlElement(
                        type = ChangeReadSequenceNumberAction.class,
                        name = "ChangeReadSequenceNumber"),
                @XmlElement(
                        type = ChangeReadMessageSequenceAction.class,
                        name = "ChangeReadMessageSequence"),
                @XmlElement(type = ChangeWriteEpochAction.class, name = "ChangeWriteEpoch"),
                @XmlElement(
                        type = ChangeWriteSequenceNumberAction.class,
                        name = "ChangeWriteSequenceNumber"),
                @XmlElement(
                        type = ChangeWriteMessageSequenceAction.class,
                        name = "ChangeWriteMessageSequence"),
                @XmlElement(type = ClearBuffersAction.class, name = "ClearBuffers"),
                @XmlElement(type = ClearDigestAction.class, name = "ClearDigest"),
                @XmlElement(type = ConnectionBoundAction.class, name = "ConnectionBound"),
                @XmlElement(type = CopyBufferedMessagesAction.class, name = "CopyBufferedMessages"),
                @XmlElement(type = CopyBufferedRecordsAction.class, name = "CopyBufferedRecords"),
                @XmlElement(type = CopyBuffersAction.class, name = "CopyBuffers"),
                @XmlElement(type = CopyClientRandomAction.class, name = "CopyClientRandom"),
                @XmlElement(type = CopyContextFieldAction.class, name = "CopyContextField"),
                @XmlElement(type = CopyPreMasterSecretAction.class, name = "CopyPreMasterSecret"),
                @XmlElement(type = CopyServerRandomAction.class, name = "CopyServerRandom"),
                @XmlElement(type = DeactivateDecryptionAction.class, name = "DeactivateDecryption"),
                @XmlElement(type = DeactivateEncryptionAction.class, name = "DeactivateEncryption"),
                @XmlElement(
                        type = DeepCopyBufferedMessagesAction.class,
                        name = "DeepCopyBufferedMessages"),
                @XmlElement(
                        type = DeepCopyBufferedRecordsAction.class,
                        name = "DeepCopyBufferedRecords"),
                @XmlElement(type = DeepCopyBuffersAction.class, name = "DeepCopyBuffers"),
                @XmlElement(type = EsniKeyDnsRequestAction.class, name = "EsniKeyDnsRequest"),
                @XmlElement(type = EchConfigDnsRequestAction.class, name = "EchConfigDnsRequest"),
                @XmlElement(
                        type = FindReceivedProtocolMessageAction.class,
                        name = "FindReceivedProtocolMessage"),
                @XmlElement(type = ForwardMessagesAction.class, name = "ForwardMessages"),
                @XmlElement(
                        type = ForwardMessagesWithPrepareAction.class,
                        name = "ForwardMessagesWithPrepare"),
                @XmlElement(type = ForwardDataAction.class, name = "ForwardData"),
                @XmlElement(type = GenericReceiveAction.class, name = "GenericReceive"),
                @XmlElement(type = ReceiveTillAction.class, name = "ReceiveTill"),
                @XmlElement(type = TightReceiveAction.class, name = "TightReceive"),
                @XmlElement(type = MultiReceiveAction.class, name = "MultiReceive"),
                @XmlElement(type = PopAndSendAction.class, name = "PopAndSend"),
                @XmlElement(type = PopAndSendMessageAction.class, name = "PopAndSendMessage"),
                @XmlElement(type = PopAndSendRecordAction.class, name = "PopAndSendRecord"),
                @XmlElement(type = PopBuffersAction.class, name = "PopBuffers"),
                @XmlElement(type = PopBufferedMessageAction.class, name = "PopBufferedMessage"),
                @XmlElement(type = PopBufferedRecordAction.class, name = "PopBufferedRecord"),
                @XmlElement(
                        type = PrintLastHandledApplicationDataAction.class,
                        name = "PrintLastHandledApplicationData"),
                @XmlElement(
                        type = PrintProposedExtensionsAction.class,
                        name = "PrintProposedExtensions"),
                @XmlElement(type = PrintSecretsAction.class, name = "PrintSecrets"),
                @XmlElement(type = ReceiveAction.class, name = "Receive"),
                @XmlElement(type = RemBufferedChCiphersAction.class, name = "RemBufferedChCiphers"),
                @XmlElement(
                        type = RemBufferedChExtensionsAction.class,
                        name = "RemBufferedChExtensions"),
                @XmlElement(type = RenegotiationAction.class, name = "Renegotiation"),
                @XmlElement(
                        type = ResetRecordCipherListsAction.class,
                        name = "ResetRecordCipherLists"),
                @XmlElement(type = ResetConnectionAction.class, name = "ResetConnection"),
                @XmlElement(type = SendAction.class, name = "Send"),
                @XmlElement(
                        type = SendDynamicClientKeyExchangeAction.class,
                        name = "SendDynamicClientKeyExchange"),
                @XmlElement(
                        type = SendDynamicServerKeyExchangeAction.class,
                        name = "SendDynamicServerKeyExchange"),
                @XmlElement(
                        type = SendDynamicServerCertificateAction.class,
                        name = "SendDynamicCertificate"),
                @XmlElement(type = SendRaccoonCkeAction.class, name = "SendRaccoonCke"),
                @XmlElement(
                        type = SendMessagesFromLastFlightAction.class,
                        name = "SendMessagesFromLastFlight"),
                @XmlElement(
                        type = SendRecordsFromLastFlightAction.class,
                        name = "SendRecordsFromLastFlight"),
                @XmlElement(
                        type = SetEncryptChangeCipherSpecConfigAction.class,
                        name = "SetEncryptChangeCipherSpecConfig"),
                @XmlElement(type = WaitAction.class, name = "Wait"),
                @XmlElement(type = FlushSessionCacheAction.class, name = "FlushSessionCache"),
                @XmlElement(type = SendAsciiAction.class, name = "SendAscii"),
                @XmlElement(type = ReceiveAsciiAction.class, name = "ReceiveAscii"),
                @XmlElement(type = GenericReceiveAsciiAction.class, name = "GenericReceiveAscii"),
            })
    private List<TlsAction> tlsActions = new ArrayList<>();

    private String name = null;
    private String description = null;

    // A dirty flag used to determine if the WorkflowTrace is well defined or
    // not.
    @XmlTransient private boolean dirty = true;

    public WorkflowTrace() {
        this.tlsActions = new LinkedList<>();
    }

    public WorkflowTrace(List<AliasedConnection> cons) {
        this.connections = cons;
    }

    public void reset() {
        for (TlsAction action : getTlsActions()) {
            action.reset();
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<TlsAction> getTlsActions() {
        return tlsActions;
    }

    public void addTlsAction(TlsAction action) {
        dirty = true;
        tlsActions.add(action);
    }

    public void addTlsAction(int position, TlsAction action) {
        dirty = true;
        tlsActions.add(position, action);
    }

    public void addTlsActions(TlsAction... actions) {
        addTlsActions(Arrays.asList(actions));
    }

    public void addTlsActions(List<TlsAction> actions) {
        for (TlsAction action : actions) {
            addTlsAction(action);
        }
    }

    public TlsAction removeTlsAction(int index) {
        dirty = true;
        return tlsActions.remove(index);
    }

    public void setTlsActions(List<TlsAction> tlsActions) {
        dirty = true;
        this.tlsActions = tlsActions;
    }

    public void setTlsActions(TlsAction... tlsActions) {
        setTlsActions(new ArrayList<>(Arrays.asList(tlsActions)));
    }

    public List<AliasedConnection> getConnections() {
        return connections;
    }

    /**
     * Set connections of the workflow trace. Use only if you know what you are doing. Unless you
     * are manually configuring workflow traces (say for MiTM or unit tests), there shouldn't be any
     * need to call this method.
     *
     * @param connections new connection to use with this workflow trace
     */
    public void setConnections(List<AliasedConnection> connections) {
        dirty = true;
        this.connections = connections;
    }

    /**
     * Add a connection to the workflow trace. Use only if you know what you are doing. Unless you
     * are manually configuring workflow traces (say for MiTM or unit tests), there shouldn't be any
     * need to call this method.
     *
     * @param connection new connection to add to the workflow trace
     */
    public void addConnection(AliasedConnection connection) {
        dirty = true;
        this.connections.add(connection);
    }

    public List<MessageAction> getMessageActions() {
        List<MessageAction> messageActions = new LinkedList<>();
        for (TlsAction action : tlsActions) {
            if (action instanceof MessageAction) {
                messageActions.add((MessageAction) action);
            }
        }
        return messageActions;
    }

    public List<ReceivingAction> getReceivingActions() {
        List<ReceivingAction> receiveActions = new LinkedList<>();
        for (TlsAction action : tlsActions) {
            if (action instanceof ReceivingAction) {
                receiveActions.add((ReceivingAction) action);
            }
        }
        return receiveActions;
    }

    public List<SendingAction> getSendingActions() {
        List<SendingAction> sendActions = new LinkedList<>();
        for (TlsAction action : tlsActions) {
            if (action instanceof SendingAction) {
                sendActions.add((SendingAction) action);
            }
        }
        return sendActions;
    }

    /**
     * Get the last TlsAction of the workflow trace.
     *
     * @return the last TlsAction of the workflow trace. Null if no actions are defined
     */
    public TlsAction getLastAction() {
        int size = tlsActions.size();
        if (size != 0) {
            return tlsActions.get(size - 1);
        }
        return null;
    }

    /**
     * Get the last MessageAction of the workflow trace.
     *
     * @return the last MessageAction of the workflow trace. Null if no message actions are defined
     */
    public MessageAction getLastMessageAction() {
        for (int i = tlsActions.size() - 1; i >= 0; i--) {
            if (tlsActions.get(i) instanceof MessageAction) {
                return (MessageAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the last SendingAction of the workflow trace.
     *
     * @return the last SendingAction of the workflow trace. Null if no sending actions are defined
     */
    public SendingAction getLastSendingAction() {
        for (int i = tlsActions.size() - 1; i >= 0; i--) {
            if (tlsActions.get(i) instanceof SendingAction) {
                return (SendingAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the last ReceivingActionAction of the workflow trace.
     *
     * @return the last ReceivingActionAction of the workflow trace. Null if no receiving actions
     *     are defined
     */
    public ReceivingAction getLastReceivingAction() {
        for (int i = tlsActions.size() - 1; i >= 0; i--) {
            if (tlsActions.get(i) instanceof ReceivingAction) {
                return (ReceivingAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the first MessageAction of the workflow trace.
     *
     * @return the first MessageAction of the workflow trace. Null if no message actions are defined
     */
    public MessageAction getFirstMessageAction() {
        for (int i = 0; i < tlsActions.size(); i++) {
            if (tlsActions.get(i) instanceof MessageAction) {
                return (MessageAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the first SendingAction of the workflow trace.
     *
     * @return the first SendingAction of the workflow trace. Null if no sending actions are defined
     */
    public SendingAction getFirstSendingAction() {
        for (int i = 0; i < tlsActions.size(); i++) {
            if (tlsActions.get(i) instanceof SendingAction) {
                return (SendingAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    /**
     * Get the first ReceivingActionAction of the workflow trace.
     *
     * @return the first ReceivingActionAction of the workflow trace. Null if no receiving actions
     *     are defined
     */
    public ReceivingAction getFirstReceivingAction() {
        for (int i = 0; i < tlsActions.size(); i++) {
            if (tlsActions.get(i) instanceof ReceivingAction) {
                return (ReceivingAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Trace Actions:");
        for (TlsAction action : tlsActions) {
            sb.append("\n");
            sb.append(action.toString());
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 23 * hash + Objects.hashCode(this.tlsActions);
        hash = 23 * hash + Objects.hashCode(this.name);
        hash = 23 * hash + Objects.hashCode(this.description);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final WorkflowTrace other = (WorkflowTrace) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.description, other.description)) {
            return false;
        }
        return Objects.equals(this.tlsActions, other.tlsActions);
    }

    public boolean executedAsPlanned() {
        for (TlsAction action : tlsActions) {
            if (!action.executedAsPlanned()
                    && !action.getActionOptions().contains(ActionOption.MAY_FAIL)) {
                LOGGER.debug("Action " + action.toCompactString() + " did not execute as planned");
                return false;
            } else {
                LOGGER.debug("Action " + action.toCompactString() + " executed as planned");
            }
        }
        return true;
    }

    public boolean allActionsExecuted() {
        for (TlsAction action : tlsActions) {
            if (!action.isExecuted()) {
                return false;
            }
        }
        return true;
    }

    public boolean isDirty() {
        return dirty;
    }

    public void setDirty(boolean dirty) {
        this.dirty = dirty;
    }

    public <T extends TlsAction> T getFirstAction(Class<T> actionCls) {
        List<TlsAction> actions = this.getTlsActions();
        for (TlsAction action : actions) {
            if (action.getClass().equals(actionCls)) {
                return actionCls.cast(action);
            }
        }
        return null;
    }

    public <T extends ProtocolMessage> T getFirstReceivedMessage(Class<T> msgClass) {
        List<ProtocolMessage> messageList = WorkflowTraceUtil.getAllReceivedMessages(this);
        messageList =
                messageList.stream()
                        .filter(i -> msgClass.isAssignableFrom(i.getClass()))
                        .collect(Collectors.toList());

        if (messageList.isEmpty()) {
            return null;
        } else {
            return (T) messageList.get(0);
        }
    }

    public <T extends ProtocolMessage> T getLastReceivedMessage(Class<T> msgClass) {
        List<ProtocolMessage> messageList = WorkflowTraceUtil.getAllReceivedMessages(this);
        messageList =
                messageList.stream()
                        .filter(i -> msgClass.isAssignableFrom(i.getClass()))
                        .collect(Collectors.toList());

        if (messageList.isEmpty()) {
            return null;
        } else {
            return (T) messageList.get(messageList.size() - 1);
        }
    }

    public <T extends ProtocolMessage> T getFirstSendMessage(Class<T> msgClass) {
        List<ProtocolMessage> messageList = WorkflowTraceUtil.getAllSendMessages(this);
        messageList =
                messageList.stream()
                        .filter(i -> msgClass.isAssignableFrom(i.getClass()))
                        .collect(Collectors.toList());

        if (messageList.isEmpty()) {
            return null;
        } else {
            return (T) messageList.get(0);
        }
    }

    public <T extends ProtocolMessage> T getLastSendMessage(Class<T> msgClass) {
        List<ProtocolMessage> messageList = WorkflowTraceUtil.getAllSendMessages(this);
        messageList =
                messageList.stream()
                        .filter(i -> msgClass.isAssignableFrom(i.getClass()))
                        .collect(Collectors.toList());

        if (messageList.isEmpty()) {
            return null;
        } else {
            return (T) messageList.get(messageList.size() - 1);
        }
    }

    public List<MessageAction> getMessageActionsWithUnreadBytes() {
        return WorkflowTraceUtil.getMessageActionsWithUnreadBytes(this);
    }

    public boolean hasUnreadByte() {
        return WorkflowTraceUtil.hasUnreadBytes(this);
    }
}
