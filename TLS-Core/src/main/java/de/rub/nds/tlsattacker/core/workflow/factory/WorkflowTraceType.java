/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

public enum WorkflowTraceType {
    FULL,
    HANDSHAKE,
    DYNAMIC_HANDSHAKE,
    DYNAMIC_HELLO,
    HELLO,
    SHORT_HELLO,
    RESUMPTION,
    FULL_RESUMPTION,
    CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION,
    CLIENT_RENEGOTIATION,
    SERVER_RENEGOTIATION,
    DYNAMIC_CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION,
    HTTPS,
    POP3,
    POP3_STARTTLS,
    SMTP,
    SMTP_STARTTLS,
    DYNAMIC_HTTPS,
    SSL2_HELLO,
    SIMPLE_MITM_PROXY,
    SIMPLE_FORWARDING_MITM_PROXY,
    TLS13_PSK,
    FULL_TLS13_PSK,
    ZERO_RTT,
    FULL_ZERO_RTT,
    FALSE_START,
    RSA_SYNC_PROXY,
    QUIC_VERSION_NEGOTIATION,
    QUIC_RETRY_HANDSHAKE,
    QUIC_PORT_CONNECTION_MIGRATION,
    QUIC_IPV6_CONNECTION_MIGRATION,
}
