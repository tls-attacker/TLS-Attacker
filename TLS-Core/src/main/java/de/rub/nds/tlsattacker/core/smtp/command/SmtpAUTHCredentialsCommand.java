package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCredentialsParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;

import java.io.InputStream;

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
}
