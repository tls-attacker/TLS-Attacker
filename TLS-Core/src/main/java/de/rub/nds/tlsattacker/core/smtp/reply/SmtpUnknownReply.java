/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
    Models unrecognized replies. This class is not supported yet.
 */
@XmlRootElement
public class SmtpUnknownReply extends SmtpReply {

    // TODO: implement. define relevant attributes.
    @Override
    public SmtpReplyParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        throw new UnsupportedOperationException("Unknown replies are not supported yet.");
    }
}
