package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SmtpMessage extends Message<SmtpContext> {

    @Override
    public abstract SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext);

    @Override
    public abstract SmtpMessageParser<? extends SmtpMessage> getParser(SmtpContext context, InputStream stream);

    @Override
    public abstract SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context);

    @Override
    public abstract SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context);
}
