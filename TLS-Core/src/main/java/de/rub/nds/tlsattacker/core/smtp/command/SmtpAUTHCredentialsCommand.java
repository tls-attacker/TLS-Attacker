package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCredentialsParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.AUTHCredentialsCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

@XmlRootElement
public class SmtpAUTHCredentialsCommand extends SmtpCommand {
    String credentials;

    public SmtpAUTHCredentialsCommand() {
        super(null, null);
    }

    public SmtpAUTHCredentialsCommand(String credentials) {
        super(null, null);
        this.credentials = credentials;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    @Override
    public AUTHCredentialsParser getParser(SmtpContext context, InputStream stream) {
        return new AUTHCredentialsParser(stream);
    }

    @Override
    public AUTHCredentialsCommandPreparator getPreparator(SmtpContext context) {
        return new AUTHCredentialsCommandPreparator(context, this);
    }
}
