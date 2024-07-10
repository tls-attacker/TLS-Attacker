package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATACommand;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpDATAReply extends SmtpReply{

    private String dataMessage;

    public SmtpDATAReply() {}

    public String getDataMessage() {
        return dataMessage;
    }

    public void setDataMessage(String dataMessage) {
        this.dataMessage = dataMessage;
    }
}
