/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ConnectionEnd {

    private String alias;
    private TlsContext context;

    public ConnectionEnd(String alias) {
        this.alias = alias;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public TlsContext getContext() {
        return context;
    }

}
