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

@XmlRootElement
public class SmtpDATAContentReply extends SmtpReply {

    private String dataMessage;

    public SmtpDATAContentReply() {}

    public String getDataMessage() {
        return dataMessage;
    }

    @Override
    public DATAContentReplyParser getParser(SmtpContext context, InputStream stream) {
        return new DATAContentReplyParser(stream);
    }

    public DATAContentReplyPreparator getPreparator(SmtpContext context) {
        return new DATAContentReplyPreparator(context, this);
    }

    public void setDataMessage(String dataMessage) {
        this.dataMessage = dataMessage;
    }
}
