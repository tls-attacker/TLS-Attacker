/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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

    public FingerprintExtractionException(String string, Throwable throwable) {
        super(string, throwable);
    }

    public FingerprintExtractionException(Throwable throwable) {
        super(throwable);
    }

    public FingerprintExtractionException(String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }

}
