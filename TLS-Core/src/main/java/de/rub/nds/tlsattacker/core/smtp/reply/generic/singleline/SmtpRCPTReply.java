/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.RCPTReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.RCPTReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class represents an SMTP RCPT reply, which indicates the server's response to a previous
 * RCPT command. The reply message contains a reply code and additional human-readable information.
 * When the reply does not follow that syntax, the valid parameter is set to False.
 */
@XmlRootElement
public class SmtpRCPTReply extends SmtpReply {

    public SmtpRCPTReply() {
        super();
        // set reply code for success
        this.setReplyCode(250);
    }

    public SmtpRCPTReply(int replyCode) {
        super();
        this.setReplyCode(replyCode);
    }

    public RCPTReplyHandler getHandler(SmtpContext context) {
        return new RCPTReplyHandler(context);
    }

    @Override
    public RCPTReplyParser getParser(SmtpContext context, InputStream stream) {
        return new RCPTReplyParser(stream);
    }
}
