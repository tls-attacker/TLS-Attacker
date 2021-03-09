/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
