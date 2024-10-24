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
import de.rub.nds.tlsattacker.core.smtp.parser.reply.EXPNReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the reply to the EXPN command.
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpEXPNCommand
 */
@XmlRootElement
public class SmtpEXPNReply extends SmtpReply {
    public static class SmtpEXPNData {
        String username;
        String mailbox;

        SmtpEXPNData(String username, String mailbox) {
            this.username = username;
            this.mailbox = mailbox;
        }

        SmtpEXPNData(String mailbox) {
            this.mailbox = mailbox;
        }

        public String getUsername() {
            return username;
        }

        public String getMailbox() {
            return mailbox;
        }

        public String serialize() {
            StringBuilder sb = new StringBuilder();

            if (this.username != null) {
                sb.append(this.username);
                sb.append(' ');
            }
            sb.append(this.mailbox);

            return sb.toString();
        }
    }

    private final List<SmtpEXPNData> data = new ArrayList<>();

    public void addMailbox(String mailbox) {
        this.data.add(new SmtpEXPNData(mailbox));
    }

    public void addUsernameAndMailbox(String username, String mailbox) {
        this.data.add(new SmtpEXPNData(username, mailbox));
    }

    public List<SmtpEXPNData> getData() {
        return data;
    }

    @Override
    public EXPNReplyParser getParser(SmtpContext context, InputStream stream) {
        return new EXPNReplyParser(stream);
    }

    @Override
    public String serialize() {
        char SP = ' ';
        char DASH = '-';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        String replyCodePrefix =
                this.replyCode != null ? String.valueOf(this.replyCode) + DASH : "";

        for (int i = 0; i < this.data.size() - 1; i++) {
            SmtpEXPNData expnData = this.data.get(i);
            sb.append(replyCodePrefix);
            sb.append(expnData.serialize());
            sb.append(CRLF);
        }

        sb.append(this.replyCode);
        sb.append(SP);
        sb.append(this.data.get(this.data.size() - 1).serialize());
        sb.append(CRLF);

        return sb.toString();
    }
}
