/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

/**
 * Defines the connection end. Either client or server.
 * 
 * @author juraj
 */
public enum ConnectionEnd {

    CLIENT,
    SERVER;

    public ConnectionEnd getPeer() {
        if (this == CLIENT) {
            return SERVER;
        } else {
            return CLIENT;
        }
    }

}
