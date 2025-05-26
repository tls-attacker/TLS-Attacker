/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

/**
 * Bit definitions for the DTLS 1.3 Unified Header as specified in RFC 9147. The header bits are
 * placed out as: 0 0 1| C | S | L | E E.
 */
public class Dtls13UnifiedHeaderBits {

    /** Base value of the unified header: the three high bits are set to 001. */
    public static final int HEADER_BASE = 0x20;

    /** Flag indicating that the Connection ID field is present (C bit). */
    public static final int CID_PRESENT = 0x10;

    /** Flag indicating that a 16-bit sequence number is used (S bit). */
    public static final int SQN_LONG = 0x08;

    /** Flag indicating that the length field is present (L bit). */
    public static final int LENGTH_PRESENT = 0x04;

    /** Mask for extracting the two low-order bits of the epoch (E E bits). */
    public static final int EPOCH_BITS = 0x03;

    private Dtls13UnifiedHeaderBits() {}
}
