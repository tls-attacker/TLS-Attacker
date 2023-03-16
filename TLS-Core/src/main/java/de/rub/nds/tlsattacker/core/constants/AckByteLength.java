/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public class AckByteLength {

    /** length of the length field for the record numbers */
    public static final int RECORD_NUMBERS_LENGTH = 2;

    public static final int RECORD_NUMBER = 16;

    private AckByteLength() {}
}
