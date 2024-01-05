/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public class RecordSizeLimit {

    public static final Integer MIN_RECORD_SIZE_LIMIT = 64;
    /**
     * RecordSizeLimit is uint16. TODO: decide if it would be interesting to go out of bounds here.
     * that would also need some tweaking around the basic classes as they have to support byte
     * lengths &gt; 2
     */
    public static final Integer MAX_RECORD_SIZE_LIMIT = 65535;
    /**
     * RFC 8449 suggests the limit for TLS 1.2 (and earlier) to be 2^14 bytes and for TLS 1.3 2^14 +
     * 1 bytes. We opt to go for the lowest common value here which is 2^14 bytes.
     */
    public static final Integer DEFAULT_MAX_RECORD_DATA_SIZE = 16384;
}
