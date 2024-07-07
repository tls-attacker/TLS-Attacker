package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;

import java.io.InputStream;

public class VRFYCommandParser extends SmtpCommandParser<SmtpVRFYCommand> {
    public VRFYCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Parses VRFY-Command.
     *
     * @param command Instance of the VRFY command class.
     * @param parameter Parameter of the VRFY command. According to RFC5321, the syntax of a full command is:
     *                                                  VRFY SP String CRLF
     *                   The string (here: parameter) may be: (a) just a username [username] or
     *                   (b) just a mailbox [local-part@domain] (see section 4.1.1.6 of RFC).
     *                   The parameter string may be an atom string (alphanumeric) or a quoted string.
     *                   In case of a mailbox, the local-part of it may also be a quoted string.
     */
    @Override
    public void parseArguments(SmtpVRFYCommand command, String parameter) {
        if (SmtpSyntaxParser.isNotAQuotedString(parameter)) {
            if (SmtpSyntaxParser.isValidAtomString(parameter)) command.setUsername(parameter);
            // mailbox can't be in an atom string, so there's no need to check if it's valid
            else throwInvalidParameterException();

            return;
        }

        // case: quoted string:
        parameter = parameter.substring(1, parameter.length() - 1); // strip outermost quotes
        if (SmtpSyntaxParser.isValidMailbox(parameter)) command.setMailbox(parameter);
        else if (SmtpSyntaxParser.isValidQuotedStringContent(parameter)) command.setUsername(parameter);
        else throwInvalidParameterException();
    }

    private void throwInvalidParameterException() {
        throw new ParserException("Malformed VRFY-Command: " +
                "the provided parameter is neither a valid username nor a valid mailbox.");
    }

    @Override
    public boolean hasParameters() {
        return true;
    }
}
