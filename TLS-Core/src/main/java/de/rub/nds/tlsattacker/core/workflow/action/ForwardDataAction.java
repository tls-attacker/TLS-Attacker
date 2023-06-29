/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardDataAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;

    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient protected boolean executedAsPlanned = false;

    public ForwardDataAction() {}

    public ForwardDataAction(String receiveFromAlias, String forwardToAlias) {
        this.receiveFromAlias = receiveFromAlias;
        this.forwardToAlias = forwardToAlias;
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        Context receiveFromCtx = state.getContext(receiveFromAlias);
        Context forwardToCtx = state.getContext(forwardToAlias);

        byte[] data = receiveData(receiveFromCtx);
        sendData(forwardToCtx, data);
        setExecuted(true);
        executedAsPlanned = true;
    }

    private byte[] receiveData(Context receiveFromContext) {
        LOGGER.debug("Receiving Messages...");
        LayerStack layerStack = receiveFromContext.getLayerStack();
        try {
            layerStack.getLowestLayer().receiveData();
            return layerStack
                    .getLowestLayer()
                    .getDataStream()
                    .readChunk(layerStack.getLowestLayer().getDataStream().available());
        } catch (IOException ex) {
            LOGGER.warn(ex);
            return new byte[0];
        }
    }

    private void sendData(Context forwardToContext, byte[] data) {
        LayerStack layerStack = forwardToContext.getLayerStack();
        try {
            layerStack.getLowestLayer().sendData(null, data);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        }
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    @Override
    public void reset() {
        executedAsPlanned = false;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 89 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 89 * hash + Objects.hashCode(this.executedAsPlanned);
        return hash;
    }

    /**
     * TODO: the equals methods for message/record actions and similar classes would require that
     * messages and records implement equals for a proper implementation. The present approach is
     * not satisfying.
     */
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
        final ForwardDataAction other = (ForwardDataAction) obj;
        if (!Objects.equals(this.receiveFromAlias, other.receiveFromAlias)) {
            return false;
        }
        if (!Objects.equals(this.forwardToAlias, other.forwardToAlias)) {
            return false;
        }
        if (!Objects.equals(this.executedAsPlanned, other.executedAsPlanned)) {
            return false;
        }
        return true;
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(forwardToAlias);
        aliases.add(receiveFromAlias);
        return aliases;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((receiveFromAlias == null) || (receiveFromAlias.isEmpty())) {
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new ActionExecutionException(
                    "Can't execute "
                            + this.getClass().getSimpleName()
                            + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    @Override
    public void filter(TlsAction defaultAction) {
        super.filter(defaultAction);
    }
}
