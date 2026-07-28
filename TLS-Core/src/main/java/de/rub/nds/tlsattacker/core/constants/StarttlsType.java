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
 * The application protocols that can be upgraded to TLS via a StartTLS handshake.
 *
 * <p>Which layer stack a type needs is decided by {@code StarttlsDelegate}, not here. Adding a
 * protocol that negotiates the upgrade with plain text actions (the lightweight approach) only
 * requires a new constant here plus its message flow in {@code
 * WorkflowConfigurationFactory.addStartTlsActions}.
 */
public enum StarttlsType {
    NONE,
    FTP,
    IMAP,
    POP3,
    SMTP;
}
