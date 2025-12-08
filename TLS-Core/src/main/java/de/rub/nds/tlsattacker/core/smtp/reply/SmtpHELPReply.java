/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The HELP response contains helpful information for the client. It consists of a reply code and
 * human-readable message. If the reply does not follow that syntax, the validSyntax parameter is
 * set to False. HELP replies can be single or multi-line.
 *
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpHELPCommand
 * @see SmtpReply
 */
@XmlRootElement
public class SmtpHELPReply extends SmtpReply {
    public SmtpHELPReply() {
        super(SmtpCommandType.HELP);
    }
}
