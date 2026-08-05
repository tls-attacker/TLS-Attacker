/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

/**
 * Whether {@link ReceiveRegexTextAction} may give up on a reply before it has been read in full.
 *
 * <p>The action stops reading once the expected pattern has matched on a terminated line, which is
 * how every text-based STARTTLS control channel delimits its replies - FTP's {@code 234}, IMAP's
 * tagged status line, NNTP's lone dot, LMTP's space-after-code final line. What that rule cannot
 * decide is what to do while the reply still does not match: keep waiting, or abandon the upgrade.
 * That is the one thing worth stating per protocol, and it is all this enum carries.
 */
public enum TextReplyTermination {
    SINGLE_LINE,

    MULTI_LINE;

    public boolean failsFastOnMismatch() {
        return this == SINGLE_LINE;
    }
}
