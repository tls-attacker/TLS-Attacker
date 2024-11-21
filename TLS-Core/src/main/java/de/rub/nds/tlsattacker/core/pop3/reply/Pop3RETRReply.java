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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.RETRReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class Pop3RETRReply extends Pop3Reply {
    private List<String> messages = new ArrayList<>();

    public Pop3RETRReply() {
        super();
    }

    @Override
    public RETRReplyParser getParser(Pop3Context context, InputStream stream) {
        return new RETRReplyParser(stream);
    }

    public List<String> getMessages() {
        return messages;
    }

    public void setMessages(List<String> messages) {
        this.messages = messages;
    }

    public void addMessage(String message) {
        this.messages.add(message);
    }

    @Override
    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();
        sb.append(this.statusIndicator);
        sb.append(SP);
        sb.append(this.humanReadableMessage.get(0));
        sb.append(CRLF);
        for (String s : messages) {
            sb.append(s);
            sb.append(CRLF);
        }
        if (messages.size() > 1) {
            sb.append(".");
            sb.append(CRLF);
        }

        return sb.toString();
    }
}
