/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ReceiveAction extends CommonReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage<?>> expectedMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage<?>> expectedHttpMessages;

    public ReceiveAction() {
        super();
    }

    public ReceiveAction(List<ProtocolMessage<?>> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(ProtocolMessage<?>... expectedMessages) {
        super();
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(
            List<ProtocolMessage<?>> expectedMessages, List<HttpMessage<?>> expectedHttpMessages) {
        this(expectedMessages);
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public ReceiveAction(HttpMessage<?>... expectedHttpMessages) {
        this.expectedHttpMessages = new ArrayList<>(Arrays.asList(expectedHttpMessages));
    }

    public ReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage<?>> messages) {
        this(messages);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage<?>... messages) {
        this(actionOptions, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(ActionOption actionOption, List<ProtocolMessage<?>> messages) {
        this(messages);
        HashSet<ActionOption> myActionOptions = new HashSet<>();
        myActionOptions.add(actionOption);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(ActionOption actionOption, ProtocolMessage<?>... messages) {
        this(actionOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAliasAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAliasAlias);
        this.expectedMessages = messages;
    }

    public ReceiveAction(String connectionAliasAlias, ProtocolMessage<?>... messages) {
        this(connectionAliasAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");

        sb.append("\tExpected:");
        if ((expectedMessages != null)) {
            for (ProtocolMessage<?> message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if ((messages != null) && (!messages.isEmpty())) {
            for (ProtocolMessage<?> message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if ((expectedMessages != null) && (!expectedMessages.isEmpty())) {
            sb.append(" (");
            for (ProtocolMessage<?> message : expectedMessages) {
                sb.append(message.toCompactString());
                sb.append(",");
            }
            sb.deleteCharAt(sb.lastIndexOf(",")).append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.expectedMessages);
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);
        hash = 67 * hash + Objects.hashCode(this.fragments);
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
        final ReceiveAction other = (ReceiveAction) obj;
        if (!Objects.equals(this.expectedMessages, other.expectedMessages)) {
            return false;
        }
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.records, other.records)) {
            return false;
        }
        if (!Objects.equals(this.fragments, other.fragments)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public void filter() {
        super.filter();
        filterEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultCon) {
        super.filter(defaultCon);
        filterEmptyLists();
    }

    private void filterEmptyLists() {
        if (expectedMessages == null || expectedMessages.isEmpty()) {
            expectedMessages = null;
        }
        if (expectedHttpMessages == null || expectedHttpMessages.isEmpty()) {
            expectedHttpMessages = null;
        }
    }

    @Override
    protected List<LayerConfiguration<?>> createConfigurationList() {
        ArrayList<LayerConfiguration<?>> configurations = new ArrayList<>();
        if (expectedMessages == null && expectedHttpMessages == null) {
            throw new WorkflowExecutionException(
                    "ReceiveAction illegally configured. Missing Configuration");
        }
        if (expectedMessages != null) {
            configurations.add(
                    new SpecificReceiveLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, expectedMessages));
        }
        if (expectedHttpMessages != null) {
            configurations.add(
                    new SpecificReceiveLayerConfiguration<>(
                            ImplementedLayers.HTTP, expectedHttpMessages));
        }
        return configurations;
    }
}
