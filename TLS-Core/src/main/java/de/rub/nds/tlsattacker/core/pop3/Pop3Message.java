package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Pop3Message extends Message<Pop3Context> {

}
