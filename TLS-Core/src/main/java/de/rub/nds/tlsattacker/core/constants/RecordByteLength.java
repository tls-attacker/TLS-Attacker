/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public class RecordByteLength {

    /**
     * Content Type length
     */
    public static final int CONTENT_TYPE = 1;
    /**
     * Record length length
     */
    public static final int RECORD_LENGTH = 2;

    /**
     * protocol version byte length
     */
    public static final int PROTOCOL_VERSION = 2;

    public static final int SEQUENCE_NUMBER = 8;

    /**
     * epoch for DTLS
     */
    public static final int DTLS_EPOCH = 2;

    /**
     * sequence number for DTLS
     */
    public static final int DTLS_SEQUENCE_NUMBER = 6;

    private RecordByteLength() {
    }

}
