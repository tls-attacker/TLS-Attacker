package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.preparator.NOOPReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpNOOPReply extends SmtpReply {
    //TODO: shift this to Config somehow
    private String noopMessage = "OK";

    @Override
    public NOOPReplyPreparator getPreparator(SmtpContext context) {
        return new NOOPReplyPreparator(context, this);
    }

    public String getNoopMessage() {
        return noopMessage;
    }

    public void setNoopMessage(String noopMessage) {
        this.noopMessage = noopMessage;
    }
}
