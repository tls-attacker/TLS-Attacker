/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;


public class DivisionException extends Exception {

    private int round;

    public DivisionException(String message) {
        super(message);
    }

    public DivisionException(String message, int i) {
        super(message + " Error happend in round " + i);
        round = i;
    }

    public int getRound() {
        return round;
    }
}
