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
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpQUITReply;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QUITReplyParser extends SmtpReplyParser<SmtpQUITReply> {

    private static final Logger LOGGER = LogManager.getLogger();

    public QUITReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpQUITReply smtpQUITReply) {
        super.parse(smtpQUITReply);
        if (smtpQUITReply.getReplyCode() != 221) {
            throw new ParserException(
                    "Expected reply code 221 for QUIT, but got " + smtpQUITReply.getReplyCode());
        }
    }
}
