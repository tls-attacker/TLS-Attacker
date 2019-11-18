/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.exception;

public class FingerprintExtractionException extends RuntimeException {

    public FingerprintExtractionException() {
    }

    public FingerprintExtractionException(String string) {
        super(string);
    }

    public FingerprintExtractionException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public FingerprintExtractionException(Throwable thrwbl) {
        super(thrwbl);
    }

    public FingerprintExtractionException(String string, Throwable thrwbl, boolean bln, boolean bln1) {
        super(string, thrwbl, bln, bln1);
    }

}
