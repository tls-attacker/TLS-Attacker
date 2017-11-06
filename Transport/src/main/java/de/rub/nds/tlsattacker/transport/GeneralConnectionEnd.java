/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport;

/**
 * A general connection end with the ability to switch connection end type at
 * life time. Useful for testing.
 * 
 */
public class GeneralConnectionEnd extends ConnectionEnd {

    private ConnectionEndType connectionEndType = null;
    private String hostname = null;

    public void setConnectionEndType(ConnectionEndType conEndType) {
        this.connectionEndType = conEndType;
    }

    @Override
    public ConnectionEndType getConnectionEndType() {
        return connectionEndType;
    }

    @Override
    public String getHostname() {
        return hostname;
    }

    @Override
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

}
