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
