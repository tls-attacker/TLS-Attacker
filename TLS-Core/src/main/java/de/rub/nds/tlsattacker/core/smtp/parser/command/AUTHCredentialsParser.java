package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpAUTHCredentialsCommand;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class AUTHCredentialsParser extends SmtpCommandParser<SmtpAUTHCredentialsCommand> {
    public AUTHCredentialsParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(SmtpAUTHCredentialsCommand smtpCommand) {
        String credentials = parseSingleLine();
        smtpCommand.setCredentials(credentials);
    }
}
