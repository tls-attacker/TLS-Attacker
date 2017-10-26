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

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public abstract class ContextlessAction extends TlsAction {

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        // Not bound to any connections
    }

    @Override
    public void normalize() {
        // We don't need any defaults
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        // We don't need any defaults
    }

    @Override
    public void filter() {
        // We don't need any defaults
    }

    @Override
    public void filter(TlsAction defaultCon) {
        // We don't need any defaults
    }

}
