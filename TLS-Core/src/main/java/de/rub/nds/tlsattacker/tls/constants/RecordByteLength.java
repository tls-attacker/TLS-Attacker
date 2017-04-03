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
 * @author juraj
 */
public class RecordByteLength {

    /**
     * Content Type length
     *
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
    public static int EPOCH = 2;
    public static int SEQUENCE_NUMBER = 8;

}
