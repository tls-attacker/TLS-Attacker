/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.connection.Aliasable;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TlsAction that can be executed in a WorkflowTrace. The TlsAction is the basic building block for
 * WorkflowTraces. A WorkflowTrace is a list of TLSActions. Executing a WorkflowTrace means
 * iterating through this list and calling execute() on each TlsAction.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class TlsAction implements Serializable, Aliasable {

    protected static final Logger LOGGER = LogManager.getLogger();

    private static final boolean EXECUTED_DEFAULT = false;

    private Boolean executed = null;

    @XmlElementWrapper
    @XmlElements(value = {@XmlElement(type = ActionOption.class, name = "ActionOption")})
    private Set<ActionOption> actionOptions = new HashSet<>();

    // Whether the action is executed in a workflow with a single connection
    // or not. Useful to decide which information can be stripped in filter().
    @XmlTransient private Boolean singleConnectionWorkflow = true;

    @XmlTransient private final Set<String> aliases = new LinkedHashSet<>();

    public TlsAction() {}

    public boolean isExecuted() {
        if (executed == null) {
            return EXECUTED_DEFAULT;
        }
        return executed;
    }

    public void setExecuted(Boolean executed) {
        this.executed = executed;
    }

    public Boolean isSingleConnectionWorkflow() {
        return singleConnectionWorkflow;
    }

    public void setSingleConnectionWorkflow(Boolean singleConnectionWorkflow) {
        this.singleConnectionWorkflow = singleConnectionWorkflow;
    }

    public abstract void execute(State state) throws ActionExecutionException;

    public abstract void reset();

    /** Add default values and initialize empty fields. */
    public void normalize() {
        // We don't need any defaults
    }

    /**
     * Add default values from given defaultAction and initialize empty fields.
     *
     * @param defaultAction Not needed / not evaluated
     */
    public void normalize(TlsAction defaultAction) {
        // We don't need any defaults
    }

    /** Filter empty fields and default values. */
    public void filter() {}

    /**
     * Filter empty fields and default values given in defaultAction.
     *
     * @param defaultAction Not needed / not evaluated
     */
    public void filter(TlsAction defaultAction) {}

    @Override
    public String getFirstAlias() {
        return getAllAliases().iterator().next();
    }

    @Override
    public boolean containsAllAliases(Collection<String> aliases) {
        return getAllAliases().containsAll(aliases);
    }

    @Override
    public boolean containsAlias(String alias) {
        return getAllAliases().contains(alias);
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {}

    @Override
    public Set<String> getAllAliases() {
        return aliases;
    }

    /**
     * Check that the Action got executed as planned.
     *
     * @return True if the Action executed as planned
     */
    public abstract boolean executedAsPlanned();

    public boolean isMessageAction() {
        return this instanceof MessageAction;
    }

    @Override
    public String aliasesToString() {
        StringBuilder sb = new StringBuilder();
        for (String alias : getAllAliases()) {
            sb.append(alias).append(",");
        }
        sb.deleteCharAt(sb.lastIndexOf(","));
        return sb.toString();
    }

    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getSimpleName());
        if (!getAllAliases().isEmpty()) {
            sb.append(" [").append(aliasesToString()).append("]");
        }
        return sb.toString();
    }

    public final Set<ActionOption> getActionOptions() {
        return actionOptions;
    }

    public final void setActionOptions(Set<ActionOption> actionOptions) {
        this.actionOptions = actionOptions;
    }

    public final void addActionOption(ActionOption option) {
        this.actionOptions.add(option);
    }

    public List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, LayerConfiguration... unsortedLayerConfigurations) {
        return sortLayerConfigurations(
                layerStack, new LinkedList<>(Arrays.asList(unsortedLayerConfigurations)));
    }

    public List<LayerConfiguration> sortLayerConfigurations(
            LayerStack layerStack, List<LayerConfiguration> unsortedLayerConfigurations) {
        List<LayerConfiguration> sortedLayerConfigurations = new LinkedList<>();
        // iterate over all layers in the stack and assign the correct configuration
        // reset configurations to only assign a configuration to the upper most layer
        for (LayerType layerType : layerStack.getLayersInStack()) {
            ImplementedLayers layer;
            try {
                layer = (ImplementedLayers) layerType;
            } catch (ClassCastException e) {
                LOGGER.warn(
                        "Cannot assign layer "
                                + layerType.getName()
                                + "to current LayerStack. LayerType not implemented for TLSAction.");
                continue;
            }
            Optional<LayerConfiguration> layerConfiguration = Optional.empty();
            if (layer == ImplementedLayers.MESSAGE
                    || layer == ImplementedLayers.RECORD
                    || layer == ImplementedLayers.DTLS_FRAGMENT
                    || layer == ImplementedLayers.HTTP
                    || layer == ImplementedLayers.SSL2) {
                layerConfiguration =
                        unsortedLayerConfigurations.stream()
                                .filter(layerConfig -> layerConfig.getLayerType().equals(layer))
                                .findFirst();
            }
            if (layerConfiguration.isPresent()) {
                sortedLayerConfigurations.add(layerConfiguration.get());
                unsortedLayerConfigurations.remove(layerConfiguration.get());
            } else {
                sortedLayerConfigurations.add(
                        new SpecificReceiveLayerConfiguration(layerType, new LinkedList<>()));
            }
        }
        return sortedLayerConfigurations;
    }
}
