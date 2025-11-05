/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3STATReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * The pop3 stat reply contains information regarding the mail drop. This consists of the number of
 * messages in the mail drop as well as the total size of the mail drop in octets.
 */
@XmlRootElement
public class Pop3STATReply extends Pop3Reply {
    private Integer numberOfMessages;
    private Integer mailDropSize;

    public Pop3STATReply() {
        super(Pop3CommandType.STAT);
    }

    @Override
    public Pop3STATReplyParser getParser(Pop3Context context, InputStream stream) {
        return new Pop3STATReplyParser(stream);
    }

    public void setNumberOfMessages(Integer messages) {
        this.numberOfMessages = messages;
    }

    public Integer getNumberOfMessages() {
        return numberOfMessages;
    }

    public void setMailDropSize(Integer mailDropSize) {
        this.mailDropSize = mailDropSize;
    }

    public Integer getMailDropSize() {
        return mailDropSize;
    }

    /**
     * Serializes the Pop3STATReply into a string that can be sent over the network. Warning: This
     * will not serialize multiline replies correctly. STAT multiline replies are strongly
     * discouraged by RFC.
     *
     * @return The serialized string
     */
    @Override
    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        sb.append(this.statusIndicator);
        sb.append(SP);
        sb.append(this.numberOfMessages);
        sb.append(SP);
        sb.append(this.mailDropSize);
        sb.append(CRLF);

        return sb.toString();
    }
}
