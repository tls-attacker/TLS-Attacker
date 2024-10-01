/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.VRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class SmtpVRFYReply extends SmtpReply {

    public static class SmtpVRFYData {
        String username;
        String mailbox;

        SmtpVRFYData(String username, String mailbox) {
            this.username = username;
            this.mailbox = mailbox;
        }

        SmtpVRFYData(String mailbox) {
            this.mailbox = mailbox;
        }

        public String getUsername() {
            return username;
        }

        public String getMailbox() {
            return mailbox;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();

            if (this.username != null) {
                sb.append(this.username);
                sb.append(' ');
            }
            sb.append(this.mailbox);

            return sb.toString();
        }
    }

    private final List<SmtpVRFYData> data = new ArrayList<>();

    public void addMailbox(String mailbox) {
        this.data.add(new SmtpVRFYData(mailbox));
    }

    public void addUsernameAndMailbox(String username, String mailbox) {
        this.data.add(new SmtpVRFYData(username, mailbox));
    }

    public List<SmtpVRFYData> getData() {
        return data;
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    @Override
    public String toString() {
        char SP = ' ';
        char DASH = '-';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        String replyCodePrefix =
                this.replyCode != null ? String.valueOf(this.replyCode) + DASH : "";

        for (int i = 0; i < this.data.size() - 1; i++) {
            SmtpVRFYData vrfyData = this.data.get(i);
            sb.append(replyCodePrefix);
            sb.append(vrfyData.toString());
            sb.append(CRLF);
        }

        sb.append(this.replyCode);
        sb.append(SP);
        sb.append(this.data.get(this.data.size() - 1).toString());
        sb.append(CRLF);

        return sb.toString();
    }
}
