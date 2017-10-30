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
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.WaitingAction;
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
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger(WorkflowTrace.class);

    @XmlElements(value = { @XmlElement(type = AliasedConnection.class, name = "AliasedConnection"),
            @XmlElement(type = InboundConnection.class, name = "InboundConnection"),
            @XmlElement(type = OutboundConnection.class, name = "OutboundConnection") })
    private List<AliasedConnection> connections = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = TlsAction.class, name = "TlsAction"),
            @XmlElement(type = ForwardAction.class, name = "ForwardAction"),
            @XmlElement(type = SendAction.class, name = "SendAction"),
            @XmlElement(type = ReceiveAction.class, name = "ReceiveAction"),
            @XmlElement(type = DeactivateEncryptionAction.class, name = "DeactivateEncryptionAction"),
            @XmlElement(type = ChangeCipherSuiteAction.class, name = "ChangeCipherSuiteAction"),
            @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompressionAction"),
            @XmlElement(type = ChangeMasterSecretAction.class, name = "ChangeMasterSecretAction"),
            @XmlElement(type = ChangePreMasterSecretAction.class, name = "ChangePreMasterSecretAction"),
            @XmlElement(type = WaitingAction.class, name = "Wait"),
            @XmlElement(type = ResetConnectionAction.class, name = "ResetConnection"),
            @XmlElement(type = ChangeProtocolVersionAction.class, name = "ChangeProtocolVersionAction"),
            @XmlElement(type = ChangeClientRandomAction.class, name = "ChangeClientRandomAction"),
            @XmlElement(type = RenegotiationAction.class, name = "RenegotiationAction"),
            @XmlElement(type = GenericReceiveAction.class, name = "GenericReceive"),
            @XmlElement(type = ChangeServerRandomAction.class, name = "ChangeServerRandomAction") })
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

    public TlsAction getLastAction() {
        int size = tlsActions.size();
        return tlsActions.get(size - 1);
    }

    public MessageAction getLastMessageAction() {
        for (int i = tlsActions.size() - 1; i > 0; i--) {
            if (tlsActions.get(i) instanceof MessageAction) {
                return (MessageAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    public SendingAction getLastSendingAction() {
        for (int i = tlsActions.size() - 1; i > 0; i--) {
            if (tlsActions.get(i) instanceof SendingAction) {
                return (SendAction) (tlsActions.get(i));
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

    public static WorkflowTrace copy(WorkflowTrace orig) {
        WorkflowTrace copy = null;
        try {
            String origTraceStr = WorkflowTraceSerializer.write(orig);
            InputStream is = new ByteArrayInputStream(origTraceStr.getBytes(StandardCharsets.UTF_8.name()));
            copy = WorkflowTraceSerializer.read(is);
        } catch (JAXBException | IOException | XMLStreamException ex) {
            throw new ConfigurationException("Could not copy workflow trace: " + ex);
        }
        return copy;
    }

}
