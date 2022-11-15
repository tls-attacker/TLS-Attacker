/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public class AckByteLength {

    /** length of the length field for the record numbers */
    public static final int RECORD_NUMBER_LENGTH_LENGTH = 2;

    public static final int RECORD_NUMBER_LENGTH = 16;

    public static final int RECORD_NUMBER_EPOCH_LENGTH = 8;

    public static final int RECORD_NUMBER_SEQUENCE_NUMBER_LENGTH = 8;

    private AckByteLength() {}
}
