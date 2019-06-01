/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.JAXBException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A wrapper class over a list of protocol expectedMessages.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Copy a workflow trace.
     *
     * TODO: This should be replaced by a better copy method. Using
     * serialization is slow and needs some additional "tweaks", i.e. we have to
     * manually restore important fields marked as XmlTransient. This problem
     * arises because the classes are configured for nice JAXB output, and not
     * for copying/storing full objects.
     *
     * @param orig
     *            the original WorkflowTrace object to copy
     * @return a copy of the original WorkflowTrace
     */
    public static WorkflowTrace copy(WorkflowTrace orig) {
        WorkflowTrace copy = null;

        List<TlsAction> origActions = orig.getTlsActions();

        try {
            String origTraceStr = WorkflowTraceSerializer.write(orig);
            InputStream is = new ByteArrayInputStream(origTraceStr.getBytes(StandardCharsets.UTF_8.name()));
            copy = WorkflowTraceSerializer.read(is);
        } catch (JAXBException | IOException | XMLStreamException ex) {
            throw new ConfigurationException("Could not copy workflow trace: " + ex);
        }

        List<TlsAction> copiedActions = copy.getTlsActions();
        for (int i = 0; i < origActions.size(); i++) {
            copiedActions.get(i).setSingleConnectionWorkflow(origActions.get(i).isSingleConnectionWorkflow());
        }

        return copy;
    }

    @XmlElements(value = { @XmlElement(type = AliasedConnection.class, name = "AliasedConnection"),
            @XmlElement(type = InboundConnection.class, name = "InboundConnection"),
            @XmlElement(type = OutboundConnection.class, name = "OutboundConnection") })
    private List<AliasedConnection> connections = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = ActivateEncryptionAction.class, name = "ActivateEncryption"),
            @XmlElement(type = ApplyBufferedMessagesAction.class, name = "ApplyBufferedMessages"),
            @XmlElement(type = BufferedGenericReceiveAction.class, name = "BufferedGenericReceive"),
            @XmlElement(type = BufferedSendAction.class, name = "BufferedSend"),
            @XmlElement(type = ChangeCipherSuiteAction.class, name = "ChangeCipherSuite"),
            @XmlElement(type = ChangeClientRandomAction.class, name = "ChangeClientRandom"),
            @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompression"),
            @XmlElement(type = ChangeMasterSecretAction.class, name = "ChangeMasterSecret"),
            @XmlElement(type = ChangePreMasterSecretAction.class, name = "ChangePreMasterSecret"),
            @XmlElement(type = ChangeProtocolVersionAction.class, name = "ChangeProtocolVersion"),
            @XmlElement(type = ChangeServerRandomAction.class, name = "ChangeServerRandom"),
            @XmlElement(type = ClearBuffersAction.class, name = "ClearBuffers"),
            @XmlElement(type = ConnectionBoundAction.class, name = "ConnectionBound"),
            @XmlElement(type = CopyBufferedMessagesAction.class, name = "CopyBufferedMessages"),
            @XmlElement(type = CopyBufferedRecordsAction.class, name = "CopyBufferedRecords"),
            @XmlElement(type = CopyBuffersAction.class, name = "CopyBuffers"),
            @XmlElement(type = CopyClientRandomAction.class, name = "CopyClientRandom"),
            @XmlElement(type = CopyContextFieldAction.class, name = "CopyContextField"),
            @XmlElement(type = CopyPreMasterSecretAction.class, name = "CopyPreMasterSecret"),
            @XmlElement(type = CopyServerRandomAction.class, name = "CopyServerRandom"),
            @XmlElement(type = DeactivateEncryptionAction.class, name = "DeactivateEncryption"),
            @XmlElement(type = DeepCopyBufferedMessagesAction.class, name = "DeepCopyBufferedMessages"),
            @XmlElement(type = DeepCopyBufferedRecordsAction.class, name = "DeepCopyBufferedRecords"),
            @XmlElement(type = DeepCopyBuffersAction.class, name = "DeepCopyBuffers"),
            @XmlElement(type = FindReceivedProtocolMessageAction.class, name = "FindReceivedProtocolMessage"),
            @XmlElement(type = ForwardMessagesAction.class, name = "ForwardMessages"),
            @XmlElement(type = ForwardMessagesWithPrepareAction.class, name = "ForwardMessagesWithPrepare"),
            @XmlElement(type = ForwardRecordsAction.class, name = "ForwardRecords"),
            @XmlElement(type = GenericReceiveAction.class, name = "GenericReceive"),
            @XmlElement(type = ReceiveTillAction.class, name = "ReceiveTill"),
            @XmlElement(type = MultiReceiveAction.class, name = "MultiReceive"),
            @XmlElement(type = PopAndSendAction.class, name = "PopAndSend"),
            @XmlElement(type = PopAndSendMessageAction.class, name = "PopAndSendMessage"),
            @XmlElement(type = PopAndSendRecordAction.class, name = "PopAndSendRecord"),
            @XmlElement(type = PopBuffersAction.class, name = "PopBuffers"),
            @XmlElement(type = PopBufferedMessageAction.class, name = "PopBufferedMessage"),
            @XmlElement(type = PopBufferedRecordAction.class, name = "PopBufferedRecord"),
            @XmlElement(type = PrintLastHandledApplicationDataAction.class, name = "PrintLastHandledApplicationData"),
            @XmlElement(type = PrintProposedExtensionsAction.class, name = "PrintProposedExtensions"),
            @XmlElement(type = PrintSecretsAction.class, name = "PrintSecrets"),
            @XmlElement(type = ReceiveAction.class, name = "Receive"),
            @XmlElement(type = RemBufferedChCiphersAction.class, name = "RemBufferedChCiphers"),
            @XmlElement(type = RemBufferedChExtensionsAction.class, name = "RemBufferedChExtensions"),
            @XmlElement(type = RenegotiationAction.class, name = "Renegotiation"),
            @XmlElement(type = ResetConnectionAction.class, name = "ResetConnection"),
            @XmlElement(type = SendAction.class, name = "Send"),
            @XmlElement(type = SendDynamicClientKeyExchangeAction.class, name = "SendDynamicClientKeyExchange"),
            @XmlElement(type = SendDynamicServerKeyExchangeAction.class, name = "SendDynamicServerKeyExchange"),
            @XmlElement(type = WaitAction.class, name = "Wait"),
            @XmlElement(type = SendAsciiAction.class, name = "SendAscii"),
            @XmlElement(type = FlushSessionCacheAction.class, name = "FlushSessionCache"),
            @XmlElement(type = GenericReceiveAsciiAction.class, name = "GenericReceiveAscii"),
            @XmlElement(type = ReceiveAsciiAction.class, name = "ReceiveAscii") })
    private List<TlsAction> tlsActions = new ArrayList<>();

    private String name = null;
    private String description = null;

    // A dirty flag used to determine if the WorkflowTrace is well defined or
    // not.
    @XmlTransient
    private boolean dirty = true;

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

    public void addTlsActions(TlsAction... actions) {
        addTlsActions(Arrays.asList(actions));
    }

    public void addTlsActions(List<TlsAction> actions) {
        for (TlsAction action : actions) {
            addTlsAction(action);
        }
    }

    public void addTlsAction(int position, TlsAction action) {
        dirty = true;
        tlsActions.add(position, action);
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
     * Set connections of the workflow trace. Use only if you know what you are
     * doing. Unless you are manually configuring workflow traces (say for MiTM
     * or unit tests), there shouldn't be any need to call this method.
     *
     * @param connections
     *            new connection to use with this workflow trace
     */
    public void setConnections(List<AliasedConnection> connections) {
        dirty = true;
        this.connections = connections;
    }

    /**
     * Add a connection to the workflow trace. Use only if you know what you are
     * doing. Unless you are manually configuring workflow traces (say for MiTM
     * or unit tests), there shouldn't be any need to call this method.
     *
     * @param connection
     *            new connection to add to the workflow trace
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
     * @return the last TlsAction of the workflow trace. Null if no actions are
     *         defined
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
     * @return the last MessageAction of the workflow trace. Null if no message
     *         actions are defined
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
     * @return the last SendingAction of the workflow trace. Null if no sending
     *         actions are defined
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
     * @return the last ReceivingActionAction of the workflow trace. Null if no
     *         receiving actions are defined
     */
    public ReceivingAction getLastReceivingAction() {
        for (int i = tlsActions.size() - 1; i >= 0; i--) {
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
            if (!action.executedAsPlanned()) {
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

}
