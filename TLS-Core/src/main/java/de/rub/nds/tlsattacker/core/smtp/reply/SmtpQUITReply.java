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
import de.rub.nds.tlsattacker.core.smtp.handler.QUITReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.QUITReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.QUITReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class SmtpQUITReply extends SmtpReply {

    private String quitMessage = "arf arf";

    public SmtpQUITReply() {
        this.replyCode = 221;
    }

    @Override
    public QUITReplyParser getParser(SmtpContext context, InputStream stream) {
        return new QUITReplyParser(stream);
    }

    public QUITReplyHandler getHandler(SmtpContext context) {
        return new QUITReplyHandler(context);
    }

    public QUITReplyPreparator getPreparator(SmtpContext context) {
        return new QUITReplyPreparator(context, this);
    }

    public String getQuitMessage() {
        return quitMessage;
    }

    public void setQuitMessage(String quitMessage) {
        this.quitMessage = quitMessage;
    }
}
