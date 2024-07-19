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
import de.rub.nds.tlsattacker.core.smtp.parser.DATAContentReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.DATAContentReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement
public class SmtpDATAContentReply extends SmtpReply {
    private List<String> lineContents;

    public SmtpDATAContentReply() {
        this.replyCode = 250;
    }

    @Override
    public DATAContentReplyParser getParser(SmtpContext context, InputStream stream) {
        return new DATAContentReplyParser(stream);
    }

    public void setLineContents(List<String> lineContents) {
        this.lineContents = lineContents;
    }

    public List<String> getLineContents() {
        return lineContents;
    }

    @Override
    public DATAContentReplyPreparator getPreparator(SmtpContext context) {
        return new DATAContentReplyPreparator(context, this);
    }
}
