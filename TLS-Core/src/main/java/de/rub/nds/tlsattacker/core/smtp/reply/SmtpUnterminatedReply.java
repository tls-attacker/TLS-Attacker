/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import java.io.InputStream;

/**
 * Models replies that do not comply to the CRLF-based format of SMTP. This should not happen in
 * practice, but is included for completeness. May indicate non-SMTP traffic.
 */
public class SmtpUnterminatedReply extends SmtpUnknownReply {
    @Override
    public SmtpReplyParser<? extends SmtpUnterminatedReply> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpReplyParser<>(stream) {
            @Override
            public void parse(SmtpUnterminatedReply message) {
                try {
                    this.parseTillEnd();
                } catch (Exception e) {
                    throw new ParserException(
                            "SmtpUnterminatedReply emptied stream and raised an exception", e);
                }
            }
        };
    }
}
