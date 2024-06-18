package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;

import java.io.InputStream;

public class MAILCommandParser extends SmtpCommandParser<SmtpMAILCommand> {
    public MAILCommandParser(InputStream stream) { super(stream);}

    @Override
    public void parseArguments(SmtpMAILCommand command, String arguments) {
        command.setReversePath(arguments);
    }

    @Override
    public  boolean hasParameters() {return true;}

}
