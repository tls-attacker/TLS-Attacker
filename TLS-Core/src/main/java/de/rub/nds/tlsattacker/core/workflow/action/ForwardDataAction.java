/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ForwardDataAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElement(name = "from")
    protected String receiveFromAlias = null;
    @XmlElement(name = "to")
    protected String forwardToAlias = null;

    @XmlTransient
    protected Boolean executedAsPlanned = null;

    public ForwardDataAction() {
    }

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
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        TlsContext receiveFromCtx = state.getTlsContext(receiveFromAlias);
        TlsContext forwardToCtx = state.getTlsContext(forwardToAlias);

        byte[] data = receiveData(receiveFromCtx);
        sendData(forwardToCtx, data);
    }

    private byte[] receiveData(TlsContext receiveFromContext) {
        LOGGER.debug("Receiving Messages...");
        LayerStack layerStack = receiveFromContext.getLayerStack();
        try {
            return layerStack.getLowestLayer().retrieveMoreData(null);
        } catch (IOException ex) {
            LOGGER.warn(ex);
            return new byte[0];
        }
    }

    private void sendData(TlsContext forwardToContext, byte[] data) {
        LayerStack layerStack = forwardToContext.getLayerStack();
        try {
            layerStack.getLowestLayer().sendData(data);
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
     * TODO: the equals methods for message/record actions and similar classes
     * would require that messages and records implement equals for a proper
     * implementation. The present approach is not satisfying.
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
        final ForwardMessagesAction other = (ForwardMessagesAction) obj;
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
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty receive alias (if using XML: add <from/>)");
        }
        if ((forwardToAlias == null) || (forwardToAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty forward alis (if using XML: add <to/>)");
        }
    }

    @Override
    public void filter(TlsAction defaultAction) {
        super.filter(defaultAction);
    }
}
