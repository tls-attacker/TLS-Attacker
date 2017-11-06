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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.WaitingAction;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A wrapper class over a list of protocol expectedMessages.
 *

 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger(WorkflowTrace.class);

    @XmlTransient
    Config config;

    @XmlElements(value = { @XmlElement(type = ConnectionEnd.class, name = "ConnectionEnd"),
            @XmlElement(type = ServerConnectionEnd.class, name = "ServerConnectionEnd"),
            @XmlElement(type = ClientConnectionEnd.class, name = "ClientConnectionEnd") })
    private List<ConnectionEnd> connectionEnds;

    /**
     * Workflow
     */
    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = TLSAction.class, name = "TLSAction"),
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
    private List<TLSAction> tlsActions;

    private String name = null;
    private String description = null;

    public WorkflowTrace() {
        this.tlsActions = new LinkedList<>();
    }

    public WorkflowTrace(Config config) {
        this.tlsActions = new LinkedList<>();
        this.config = config;
    }

    public void reset() {
        for (TLSAction action : getTlsActions()) {
            action.reset();
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void addTlsAction(TLSAction action) {
        assertValidAlias(action.getContextAlias());
        tlsActions.add(action);
    }

    public void addTlsActions(List<TLSAction> actions) {
        for (TLSAction action : actions) {
            addTlsAction(action);
        }
    }

    public void addTlsActions(TLSAction... actions) {
        addTlsActions(Arrays.asList(actions));
    }

    public void addTlsAction(int position, TLSAction action) {
        assertValidAlias(action.getContextAlias());
        tlsActions.add(position, action);
    }

    public TLSAction removeTlsAction(int index) {
        return tlsActions.remove(index);
    }

    public List<TLSAction> getTlsActions() {
        return tlsActions;
    }

    public void setTlsActions(List<TLSAction> tlsActions) {
        this.tlsActions = tlsActions;
    }

    public void setTlsActions(TLSAction... tlsActions) {
        this.tlsActions = Arrays.asList(tlsActions);
    }

    public boolean addConnectionEnd(ConnectionEnd con) {
        if (connectionEnds == null) {
            connectionEnds = new ArrayList<>();
        }
        return connectionEnds.add(con);
    }

    public void addConnectionEnd(int position, ConnectionEnd con) {
        connectionEnds.add(position, con);
    }

    public ConnectionEnd removeConnectionEnd(int index) {
        return connectionEnds.remove(index);
    }

    public List<ConnectionEnd> getConnectionEnds() {
        if (connectionEnds == null) {
            if ((config != null) && (config.getConnectionEnds() != null)) {
                return config.getConnectionEnds();
            }
            throw new ConfigurationException("This workflow trace does not know about any " + "connection end(s).");
        }
        return connectionEnds;
    }

    public void setConnectionEnds(List<ConnectionEnd> conEnds) {
        this.connectionEnds = conEnds;
    }

    public void setConnectionEnds(ConnectionEnd... conEnds) {
        this.connectionEnds = Arrays.asList(conEnds);
    }

    public void clearConnectionEnds() {
        if (connectionEnds != null) {
            connectionEnds.clear();
        }
    }

    public List<MessageAction> getMessageActions() {
        List<MessageAction> messageActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof MessageAction) {
                messageActions.add((MessageAction) action);
            }
        }
        return messageActions;
    }

    public List<ReceivingAction> getReceivingActions() {
        List<ReceivingAction> receiveActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceivingAction) {
                receiveActions.add((ReceivingAction) action);
            }
        }
        return receiveActions;
    }

    public List<SendingAction> getSendingActions() {
        List<SendingAction> sendActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof SendingAction) {
                sendActions.add((SendingAction) action);
            }
        }
        return sendActions;
    }

    public TLSAction getLastAction() {
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
        for (TLSAction action : tlsActions) {
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
        for (TLSAction action : tlsActions) {
            if (!action.executedAsPlanned()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if the given alias matches one of our connection ends.
     */
    private void assertValidAlias(String alias) {
        StringBuilder errMsg = new StringBuilder("known aliases: ");
        List<ConnectionEnd> conEnds = getConnectionEnds();
        if ((conEnds != null) && (!conEnds.isEmpty())) {
            for (ConnectionEnd conEnd : conEnds) {
                if (conEnd.getAlias().equals(alias)) {
                    return;
                }
                errMsg.append(conEnd.getAlias()).append(' ');
            }
        }
        errMsg.insert(0, "Action alias '" + alias + "' refers to an unknown connection end - ");
        throw new ConfigurationException(errMsg.toString());
    }

    public void setConfig(Config config) {
        this.config = config;
    }

}
