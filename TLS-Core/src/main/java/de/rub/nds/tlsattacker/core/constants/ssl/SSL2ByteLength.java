/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants.ssl;

/**
 * Length of fields in SSL2 Messages
 */
public class SSL2ByteLength {
    public static final int LENGTH = 2;

    public static final int LONG_LENGTH = 3;

    public static final int MESSAGE_TYPE = 1;

    public static final int VERSION = 2;

    public static final int CIPHERSUITE_LENGTH = 2;

    public static final int SESSIONID_LENGTH = 2;

    public static final int CHALLENGE_LENGTH = 2;

    public static final int SESSION_ID_HIT = 1;

    public static final int CERTIFICATE_TYPE = 1;

    public static final int CERTIFICATE_LENGTH = 2;

    public static final int CIPHERKIND_LENGTH = 3;

    public static final int CLEAR_KEY_LENGTH = 2;

    public static final int ENCRYPTED_KEY_LENGTH = 2;

    private SSL2ByteLength() {
    }
}
