/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

public enum ActionOption {
    IGNORE_UNEXPECTED_NEW_SESSION_TICKETS,
    IGNORE_UNEXPECTED_WARNINGS,
    IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES,
    IGNORE_UNEXPECTED_APP_DATA,
    IGNORE_UNEXPECTED_HTTPS_MESSAGES,
    MAY_FAIL,
    CHECK_ONLY_EXPECTED,
    QUIC_FRAMES_STRICT_PADDING,
    QUIC_FRAMES_IGNORE_NT_NCID_RTCID,
    QUIC_FRAMES_IGNORE_ACK,
    QUIC_DO_NOT_ACK_RECEPTION_OF_PACKET;
}
