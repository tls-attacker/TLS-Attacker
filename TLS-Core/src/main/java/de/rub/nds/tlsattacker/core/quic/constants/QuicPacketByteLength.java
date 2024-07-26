/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

public class QuicPacketByteLength {

    public static final int QUIC_VERSION_LENGTH = 4;

    public static final int QUIC_FIRST_HEADER_BYTE = 1;

    public static final int DESTINATION_CONNECTION_ID_LENGTH = 1;

    public static final int SOURCE_CONNECTION_ID_LENGTH = 1;

    public static final int NO_TOKEN_TOKEN_LENGTH = 1;
}
