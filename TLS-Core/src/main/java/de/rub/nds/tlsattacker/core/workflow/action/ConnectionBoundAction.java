/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

/**
 * TLS Action bound to a single connection/TLS context. This should be the
 * default abstract base class for most actions. Provides automatic fallback to
 * default context alias.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class ConnectionBoundAction extends TlsAction {

    private String connectionAlias = null;

    @XmlTransient
    private final Set<String> aliases = new HashSet<>();

    public ConnectionBoundAction() {
    }

    public ConnectionBoundAction(String alias) {
        this.connectionAlias = alias;
    }

    public String getConnectionAlias() {
        return connectionAlias;
    }

    public void setConnectionAlias(String connectionAlias) {
        this.connectionAlias = connectionAlias;
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
    };

    @Override
    public boolean containsAlias(String alias) {
        return getAllAliases().contains(alias);
    };

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((connectionAlias == null) || (connectionAlias.isEmpty())) {
            throw new ConfigurationException("connectionAlias empty or null in " + this.getClass().getSimpleName());
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
        if (isSingleConnectionWorkflow() && connectionAlias != null
                && connectionAlias.equals(AliasedConnection.DEFAULT_CONNECTION_ALIAS)) {
            connectionAlias = null;
        }
    }

    @Override
    public void filter(TlsAction defaultCon) {
        if (isSingleConnectionWorkflow() && connectionAlias != null
                && connectionAlias.equals(defaultCon.getFirstAlias())) {
            connectionAlias = null;
        }
        filter();
    }
}
