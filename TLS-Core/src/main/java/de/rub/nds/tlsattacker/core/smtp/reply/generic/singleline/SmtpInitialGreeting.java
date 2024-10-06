/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * This class represents the initial greeting of the SMTP server when a connection is established.
 * It does not have a command counterpart, but follows the same structure as the other replies.
 */
@XmlRootElement
public class SmtpInitialGreeting extends SmtpReply {

    @Override
    public String toShortString() {
        return "SMTP Initial Greeting";
    }

    public boolean serverRejection() {
        return this.getReplyCode().getValue() == 554;
    }

    public boolean serverReady() {
        return this.getReplyCode().getValue() == 220;
    }
}
