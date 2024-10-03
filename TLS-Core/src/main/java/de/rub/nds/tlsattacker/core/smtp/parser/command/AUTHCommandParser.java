package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpAUTHCommand;

import java.io.InputStream;

public class AUTHCommandParser extends SmtpCommandParser<SmtpAUTHCommand> {
    public AUTHCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpAUTHCommand command, String arguments) {
        if (arguments == null) {
            throw new ParserException("AUTH command requires parameters.");
        }

        String[] parts = arguments.split(" ", 2);

        // TODO: make more complex. just works for most basic command at the moment.
        if (parts.length >= 2) {
            command.setSaslMechanism(parts[0]);
            command.setInitialResponse(parts[1]);
            return;
        }

        if (parts.length == 1) {
            command.setSaslMechanism(parts[0]);
        }
    }
}
