package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.io.InputStream;

public class VRFYCommandParser extends SmtpCommandParser<SmtpVRFYCommand> {
    public VRFYCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Parses VRFY-Command.
     *
     * @param command Instance of the VRFY command class.
     * @param parameters Parameters of the VRFY command. According to RFC5321:
     *                   They may be just a username [username], just a mailbox [local-part@domain] or both:
     *                   [username] [local-part@domain].
     *                   The parameters string itself may be an atom string (alphanumeric) or a quoted
     *                   string containing most ascii-characters (like space). The same goes for the
     *                   local-part of the mailbox as well.
     */
    @Override
    public void parseArguments(SmtpVRFYCommand command, String parameters) {
        String parametersText = parameters;
        if (isQuotedString(parameters)) parametersText = parameters.substring(1, parameters.length() - 1); // strip quotes

        String[] dividedParameters = findUsernameAndMailboxAddress(parametersText);
        String username = dividedParameters[0];
        String mailboxAddress = dividedParameters[1];

        if (username == null && mailboxAddress == null) return;

        boolean onlyAddressIsPresent = username == null;
        boolean mailboxAddressIsValid = mailboxAddress != null && isValidMailboxAddress(mailboxAddress);
        boolean mailboxAddressIsQuotedString = mailboxAddress != null && isQuotedString(mailboxAddress);

        if (onlyAddressIsPresent && !mailboxAddressIsValid && mailboxAddressIsQuotedString) {
            /*
                a quoted-string username may contain identical characters as a mailboxAddress,
                so if the address itself is invalid, it may potentially be a valid username instead
            */
            username = mailboxAddress;
            mailboxAddress = null;
        } else if (!mailboxAddressIsValid && !mailboxAddressIsQuotedString) {
            mailboxAddress = null;
        }

        command.setUsername(username);
        command.setMailboxAddress(mailboxAddress);
    }

    private boolean isQuotedString(String string) {
        return string.length() > 1 &&
                string.charAt(0) == '"' &&
                string.charAt(string.length() - 1) == '"';
    }

    /**
     * @param parameters: Parameters of the VRFY command with outermost double quotes stripped.
     * @return An array containing two strings denoting username and mailbox address. If either is
     *         not present, the value null is provided.
     */
    private String[] findUsernameAndMailboxAddress(String parameters) {
        // 1. Find mailbox if it is present:
        int i = indexOfCharacter(parameters, parameters.length() - 1, '@'); // Mailbox must contain character '@'
        if (i < 0) return new String[]{parameters, null}; // Case: no mailbox exists in parameters

        // 2. If possible mailbox is found, find beginning of local part of mailbox:
        boolean localPartisQuotedString = i > 0 && parameters.charAt(i-1) == '"'; // only quoted strings may contain double quotes
        if (localPartisQuotedString) i = indexOfCharacter(parameters, --i, '"');
        else i = indexOfCharacter(parameters, i, ' ') + 1; // case: local part is atom string

        // 3. Return split parameters based on where the split 'i' was found:
        if (i < 0) return new String[]{parameters, null}; // case: malformed, quoted-string local part
        if (i < 2) return new String[]{null, parameters}; // case: only mailbox address is present (as username).

        return splitStringByIndex(parameters, i); // case: username and mailbox found
    }

    private String[] splitStringByIndex(String string, int index) {
        return new String[]{string.substring(0, index-1), string.substring(index)};
    }

    private int indexOfCharacter(String string, int startIndex, char character) {
        int i = startIndex;
        while(i >= 0 && string.charAt(i) != character) i--;

        return i;
    }

    /**
     * @param mailboxAddress Mailbox address from the VRFY-command parameters.
     * @return Whether mailbox address has valid syntax in accordance with RFC822.
     * TODO: check whether RFC822 compliance is equivalent to RFC5321 compliance.
     */
    private boolean isValidMailboxAddress(String mailboxAddress) {
        boolean isValid = true;
        try {
            InternetAddress internetAddress = new InternetAddress(mailboxAddress);
            internetAddress.validate();
        } catch (AddressException ex) {
            isValid = false;
        }

        return isValid;
    }
}
