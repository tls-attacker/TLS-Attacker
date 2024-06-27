package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;

import java.io.InputStream;

public class VRFYCommandParser extends SmtpCommandParser<SmtpCommand> {
    public VRFYCommandParser(InputStream stream) { super(stream);}

    /**
     * Parses VRFY-Command.
     *
     * @param command - Instance of the VRFY command class.
     * @param args - String parameter of the VRFY command.
     *             Format: "Username" or "Username <local-part@domain.com>"
     *             Username: Can be just last name or first and last name. Can also just be a standalone email-address.
     * **/
    @Override
    public void parseArguments(SmtpCommand command, String args) { // TODO: check whether VRFY command is necessary/whether command is even used
        String[] dividedArgs = args.split(" "); // division may not be necessary
        int numberOfArguments = dividedArgs.length;

        if (numberOfArguments == 0 || numberOfArguments > 3) {
            // TODO: add negative response with status code: 5yz
            return;
        }

        boolean addressIsValid = verify(args);

        if (!addressIsValid) {
            // TODO: add negative response here as well
            return;
        }

        // TODO: add positive response with status code: 2yz
    }

    public boolean verify(String address) {
        // TODO: find way to validate email address. perhaps by initiating an SMTP session with the client?
        return true;
    }

}
