package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.preparator.InitialGreetingPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * This class represents the initial greeting of the SMTP server when a connection is established.
 * It does not have a command counterpart, but follows the same structure as the other replies.
 */
@XmlRootElement
public class SmtpInitialGreeting extends SmtpReply {
    private String greeting;

    public SmtpInitialGreeting() {
        super();
    }
    public SmtpInitialGreeting(String greeting) {
        super();
        this.greeting = greeting;
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        //TODO
        return new InitialGreetingPreparator(context, this);
    }

    @Override
    public String toShortString() {
        return "SMTP Initial Greeting";
    }

    public String getGreeting() {
        return greeting;
    }

    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }

    public boolean serverRejection() {
        return this.getReplyCode() == 554;
    }
    public boolean serverReady() {
        return this.getReplyCode() == 220;
    }
}
