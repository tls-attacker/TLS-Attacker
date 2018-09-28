/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

public class TokenBindingLength {

    public final static int TOKENBINDINGS = 2;

    public final static int KEY_PARAMETER = 1;

    public final static int MODULUS = 2;

    public final static int PUBLIC_EXPONENT = 1;

    public final static int POINT = 1;

    public final static int KEY = 2;

    public final static int BINDING_TYPE = 1;

    public final static int SIGNATURE = 2;

    public final static int EXTENSIONS = 2;

    private TokenBindingLength() {
    }
}
