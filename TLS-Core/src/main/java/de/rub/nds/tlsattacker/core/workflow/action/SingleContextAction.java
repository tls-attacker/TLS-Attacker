/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

/**
 * TLS Action working on a single TLS context only. This should be the default
 * abstract base class for most actions. Provides automatic fallback to default
 * context alias.
 * 
 * Note: In order to provide proper fallback to the default TlsContext, access
 * the contextAlias only via getContextAlias().
 * 
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SingleContextAction extends TlsAction {

    private String contextAlias = null;

    public SingleContextAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public SingleContextAction(String contextAlias) {
        super(contextAlias);
        this.contextAlias = contextAlias;
    }

    public String getContextAlias() {
        return contextAlias;
    }

    public void setContextAlias(String contextAlias) {
        super.setAlias(contextAlias);
        this.contextAlias = contextAlias;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((getContextAlias() == null) || (getContextAlias().isEmpty())) {
            throw new ConfigurationException("Empty or null alias in " + this.getClass().getSimpleName());
        }
    }

    @Override
    public void normalize() {
        if (contextAlias == null || contextAlias.isEmpty()) {
            contextAlias = AliasedConnection.DEFAULT_CONNECTION_ALIAS;
        }
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        if (contextAlias == null) {
            contextAlias = defaultAction.getFirstAlias();
            normalize();
        }
    }

    @Override
    public void filter() {
        if (isSingleConnectionWorkflow() && contextAlias != null
                && contextAlias.equals(AliasedConnection.DEFAULT_CONNECTION_ALIAS)) {
            contextAlias = null;
        }
    }

    @Override
    public void filter(TlsAction defaultCon) {
        if (isSingleConnectionWorkflow() && contextAlias != null && contextAlias.equals(defaultCon.getFirstAlias())) {
            contextAlias = null;
        }
        filter();
    }
}
