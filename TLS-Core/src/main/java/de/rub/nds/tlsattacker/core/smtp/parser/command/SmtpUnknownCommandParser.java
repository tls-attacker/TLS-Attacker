package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpUnknownCommand;

import java.io.InputStream;

public class SmtpUnknownCommandParser extends SmtpCommandParser<SmtpUnknownCommand> {

    public SmtpUnknownCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Special parser for unknown commands which also accesses the verb string.
     * Other parsers do not have access to the verb string, because they are created based on the verb string matching a known verb.
     * @param smtpCommand
     */
    @Override
    public void parse(SmtpUnknownCommand smtpCommand) {
        // TODO: make this robust against not having CRLF, fails at the moment when no CR
        // parseStringTill(CRLF) is sadly not possible
        String line = parseSingleLine();
        // throws EndOfStreamException if no LF is found

        // 4.1.1 In the interest of improved interoperability, SMTP receivers SHOULD tolerate
        // trailing white space before the terminating &lt;CRLF&gt;.
        String actualCommand = line.trim();
        String[] verbAndParams = actualCommand.split(" ", 2);

        smtpCommand.setUnknownCommandVerb(verbAndParams[0]);
        if (verbAndParams.length == 2) {
            smtpCommand.setParameters(verbAndParams[1]);
        }

    }
}
