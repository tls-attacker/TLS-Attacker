/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * TLS Action bound to a single connection/TLS context. This should be the default abstract base
 * class for most actions. Provides automatic fallback to default context alias.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ConnectionBoundAction extends TlsAction {

    protected String connectionAlias = null;

    @XmlTransient private final Set<String> aliases = new HashSet<>();

    public ConnectionBoundAction() {}

    public ConnectionBoundAction(String alias) {
        this.connectionAlias = alias;
    }

    public ConnectionBoundAction(Set<ActionOption> actionOptions, String alias) {
        super(actionOptions);
        this.connectionAlias = alias;
    }

    public ConnectionBoundAction(Set<ActionOption> actionOptions) {
        super(actionOptions);
    }

    public String getConnectionAlias() {
        return connectionAlias;
    }

    public void setConnectionAlias(String connectionAlias) {
        this.connectionAlias = connectionAlias;
    }

    public boolean hasDefaultAlias() {
        return getConnectionAlias().equals(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    @Override
    public String getFirstAlias() {
        return connectionAlias;
    }

    @Override
    public Set<String> getAllAliases() {
        if (aliases.isEmpty() && (connectionAlias != null) && (!connectionAlias.isEmpty())) {
            aliases.add(connectionAlias);
        }
        return aliases;
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
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((connectionAlias == null) || (connectionAlias.isEmpty())) {
            throw new ConfigurationException(
                    "connectionAlias empty or null in " + this.getClass().getSimpleName());
        }
    }

    @Override
    public void normalize() {
        if (connectionAlias == null || connectionAlias.isEmpty()) {
            connectionAlias = AliasedConnection.DEFAULT_CONNECTION_ALIAS;
        }
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        if (connectionAlias == null || connectionAlias.isEmpty()) {
            connectionAlias = defaultAction.getFirstAlias();
            normalize();
        }
    }

    @Override
    public void filter() {
        if (!isSingleConnectionWorkflow() || connectionAlias == null) {
            return;
        }
        if (connectionAlias.equals(AliasedConnection.DEFAULT_CONNECTION_ALIAS)) {
            connectionAlias = null;
        }
    }

    @Override
    public void filter(TlsAction defaultCon) {
        if (!isSingleConnectionWorkflow() || connectionAlias == null) {
            return;
        }
        String defaultAlias = defaultCon.getFirstAlias();
        if (defaultAlias == null) {
            defaultAlias = AliasedConnection.DEFAULT_CONNECTION_ALIAS;
        }
        if (connectionAlias.equals(defaultAlias)) {
            connectionAlias = null;
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 79 * hash + Objects.hashCode(this.connectionAlias);
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
        final ConnectionBoundAction other = (ConnectionBoundAction) obj;
        return Objects.equals(this.connectionAlias, other.connectionAlias);
    }
}
