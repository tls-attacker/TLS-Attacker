/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpNOOPReply;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NOOPReplyParser extends SmtpReplyParser<SmtpNOOPReply> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NOOPReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpNOOPReply smtpNOOPReply) {
        super.parse(smtpNOOPReply);
        if (smtpNOOPReply.getReplyCode() != 250) {
            throw new ParserException(
                    "Expected reply code 250 for NOOP, but got " + smtpNOOPReply.getReplyCode());
        }
    }
}