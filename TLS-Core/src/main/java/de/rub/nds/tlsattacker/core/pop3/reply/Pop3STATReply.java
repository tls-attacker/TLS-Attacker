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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.STATReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class Pop3STATReply extends Pop3Reply {
    private String messages;
    private String octets;

    public Pop3STATReply() {
        super();
    }

    @Override
    public STATReplyParser getParser(Pop3Context context, InputStream stream) {
        return new STATReplyParser(stream);
    }

    public void setMessages(String messages) {
        this.messages = messages;
    }

    public String getMessages() {
        return messages;
    }

    public void setOctets(String octets) {
        this.octets = octets;
    }

    public String getOctets() {
        return octets;
    }

    @Override
    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        sb.append(this.statusIndicator);
        sb.append(SP);
        sb.append(this.messages);
        sb.append(SP);
        sb.append(this.octets);
        sb.append(CRLF);

        return sb.toString();
    }
}
