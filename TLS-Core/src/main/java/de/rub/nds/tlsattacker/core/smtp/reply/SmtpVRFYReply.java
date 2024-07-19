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
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.VRFYReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
public class SmtpVRFYReply extends SmtpReply {

    private List<String> mailboxes = new LinkedList<>();
    private List<String> lineContents;

    public SmtpVRFYReply() {}

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return new VRFYReplyPreparator(context, this);
    }

    public List<String> getMailboxes() {
        return mailboxes;
    }

    public void setMailboxes(List<String> mailboxes) {
        this.mailboxes = mailboxes;
    }

    public void addMailbox(String mailbox) {
        if (mailbox != null) this.mailboxes.add(mailbox);
    }

    public List<String> getLineContents() {
        return lineContents;
    }

    public void setLineContents(List<String> lineContents) {
        this.lineContents = lineContents;
    }
}
