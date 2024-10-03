package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.AUTHCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class SmtpAUTHCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "AUTH";

    // depending on the mechanism, there CAN (but don't have to) be multiple base64 strings
    private String saslMechanism; // mandatory
    private String initialResponse;

    public SmtpAUTHCommand() {
        super(COMMAND_NAME);
    }

    // E.g. "AUTH PLAIN"
    public SmtpAUTHCommand(String saslMechanism) {
        super(COMMAND_NAME, saslMechanism);
        this.saslMechanism = saslMechanism;
    }

    // E.g. "AUTH PLAIN Qts12w=="
    public SmtpAUTHCommand(String saslMechanism, String initialResponse) {
        super(COMMAND_NAME);
        this.saslMechanism = saslMechanism;
        this.initialResponse = initialResponse;
    }

    public String getSaslMechanism() {
        return saslMechanism;
    }

    public String getInitialResponse() {
        return initialResponse;
    }

    public void setSaslMechanism(String saslMechanism) {
        this.saslMechanism = saslMechanism;
    }

    public void setInitialResponse(String initialResponse) {
        this.initialResponse = initialResponse;
    }

    @Override
    public AUTHCommandParser getParser(SmtpContext context, InputStream stream) {
        return new AUTHCommandParser(stream);
    }

    @Override
    public AUTHCommandPreparator getPreparator(SmtpContext context) {
        return new AUTHCommandPreparator(context, this);
    }
}
