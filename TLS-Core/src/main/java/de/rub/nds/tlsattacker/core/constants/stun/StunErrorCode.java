/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.stun;

public enum StunErrorCode {
    TRY_ALTERNATE(300),
    BAD_REQUEST(400),
    UNAUTHENTICATED(401),
    FORBIDDEN(403),
    MOBILITY_FORBIDDEN(405),
    UNKNOWN_ATTRIBUTE(420),
    ALLOCATION_MISMATCH(437),
    STALE_NONCE(438),
    ADDRESS_FAMILY_NOT_SUPPORTED(440),
    WRONG_CREDENTIALS(441),
    UNSUPPORTED_TRANSPORT_PROTOCOL(442),
    PEER_ADDRESS_FAMILY_MISMATCH(443),
    CONNECTION_ALREADY_EXISTS(446),
    CONNECTION_TIMEOUT_OR_FAILURE(447),
    ALLOCATION_QUOTA_REACHED(486),
    ROLE_CONFLICT(487),
    SERVER_ERROR(500),
    INSUFFICIENT_CAPACITY(508);

    private final int code;

    StunErrorCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
