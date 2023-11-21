/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

public class MiscRfcConstants {

    public static final int SMALLEST_MAX_DATAGRAM_SIZE = 1200;
    public static final int MAX_ENCODED_PACKETNUMBER_LENGTH = 4;
    // TODO: actually rfc constant?
    public static final int AUTH_TAG_LENGTH = 16;
    public static final int RETRY_TOKEN_INTEGRITY_TAG_LENGTH = 16;
}
