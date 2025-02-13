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
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpEHLOReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Models the reply to the EHLO command.
 *
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand
 */
@XmlRootElement
public class SmtpEHLOReply extends SmtpReply {
    private String domain;
    private String greeting;
    private List<SmtpServiceExtension> extensions;

    public SmtpEHLOReply() {
        super();
        this.extensions = new ArrayList<>();
    }

    @Override
    public SmtpEHLOReplyParser getParser(SmtpContext context, InputStream stream) {
        return new SmtpEHLOReplyParser(stream);
    }

    public String getGreeting() {
        return greeting;
    }

    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public List<SmtpServiceExtension> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<SmtpServiceExtension> extensions) {
        this.extensions = extensions;
    }

    @Override
    public String serialize() {
        char SP = ' ';
        char DASH = '-';
        String CRLF = "\r\n";

        boolean hasExtensions = !this.extensions.isEmpty();

        StringBuilder sb = new StringBuilder();

        sb.append(this.replyCode);
        sb.append(hasExtensions ? DASH : SP);
        sb.append(this.domain);
        if (this.greeting != null) {
            sb.append(SP);
            sb.append(this.greeting);
        }
        sb.append(CRLF);

        if (!hasExtensions) return sb.toString();

        for (int i = 0; i < this.extensions.size() - 1; i++) {
            SmtpServiceExtension ext = this.extensions.get(i);
            sb.append(this.replyCode);
            sb.append(DASH);
            sb.append(ext.serialize());
            sb.append(CRLF);
        }

        sb.append(this.replyCode);
        sb.append(SP);
        sb.append(this.extensions.get(this.extensions.size() - 1).serialize());
        sb.append(CRLF);

        return sb.toString();
    }
}
