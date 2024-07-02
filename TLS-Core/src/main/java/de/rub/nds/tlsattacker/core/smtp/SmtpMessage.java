/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement
public abstract class SmtpMessage extends Message<SmtpContext> {

    @Override
    public abstract SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext);

    @Override
    public abstract SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream);

    @Override
    public abstract SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context);

    @Override
    public abstract SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context);
}
