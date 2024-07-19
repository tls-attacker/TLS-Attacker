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
import de.rub.nds.tlsattacker.core.smtp.parser.MAILReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.MAILReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class SmtpMAILReply extends SmtpReply {
    public SmtpMAILReply() {
        super();
    }

    @Override
    public MAILReplyParser getParser(SmtpContext context, InputStream stream) {
        return new MAILReplyParser(stream);
    }

    public MAILReplyPreparator getPreparator(SmtpContext context) {
        return new MAILReplyPreparator(context, this);
    }
}
