/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeProtocolVersionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private ProtocolVersion newValue;
    private ProtocolVersion oldValue = null;

    public ChangeProtocolVersionAction(ProtocolVersion newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangeProtocolVersionAction() {}

    public void setNewValue(ProtocolVersion newValue) {
        this.newValue = newValue;
    }

    public ProtocolVersion getNewValue() {
        return newValue;
    }

    public ProtocolVersion getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getSelectedProtocolVersion();
        tlsContext.setSelectedProtocolVersion(newValue);
        LOGGER.info(
                "Changed ProtocolVersion from " + oldValue == null
                        ? oldValue.name()
                        : null + " to " + newValue.name());
        setExecuted(true);
    }

    @Override
    public void reset() {
        oldValue = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 83 * hash + Objects.hashCode(this.newValue);
        hash = 83 * hash + Objects.hashCode(this.oldValue);
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
        final ChangeProtocolVersionAction other = (ChangeProtocolVersionAction) obj;
        if (this.newValue != other.newValue) {
            return false;
        }
        return this.oldValue == other.oldValue;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
