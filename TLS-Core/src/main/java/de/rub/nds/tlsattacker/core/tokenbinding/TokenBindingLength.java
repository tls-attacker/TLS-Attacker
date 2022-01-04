/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.tokenbinding;

public class TokenBindingLength {

    public static final int TOKENBINDINGS = 2;

    public static final int KEY_PARAMETER = 1;

    public static final int MODULUS = 2;

    public static final int PUBLIC_EXPONENT = 1;

    public static final int POINT = 1;

    public static final int KEY = 2;

    public static final int BINDING_TYPE = 1;

    public static final int SIGNATURE = 2;

    public static final int EXTENSIONS = 2;

    private TokenBindingLength() {
    }
}
