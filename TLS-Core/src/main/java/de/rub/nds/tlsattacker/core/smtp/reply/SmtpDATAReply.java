package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATACommand;
import de.rub.nds.tlsattacker.core.smtp.parser.DATAReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.DATAReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class SmtpDATAReply extends SmtpReply{

    private String dataMessage;

    public SmtpDATAReply() {}

    public String getDataMessage() {
        return dataMessage;
    }

    @Override
    public DATAReplyParser getParser(SmtpContext context, InputStream stream) {
        return new DATAReplyParser(stream);
    }

    public DATAReplyPreparator getPreparator(SmtpContext context) {
        return new DATAReplyPreparator(context, this);
    }

    public void setDataMessage(String dataMessage) {
        this.dataMessage = dataMessage;
    }
}
