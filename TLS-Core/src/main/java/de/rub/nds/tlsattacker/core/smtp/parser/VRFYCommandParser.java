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
     * @param parameter Parameter of the VRFY command. According to RFC5321, the syntax of a full command is:
     *                                                  VRFY SP String CRLF
     *                   The string (here: parameter) may be: (a) just a username [username] or
     *                   (b) just a mailbox [local-part@domain] (see section 4.1.1.6 of RFC).
     *                   The parameter string may be an atom string (alphanumeric) or a quoted string.
     *                   In accordance with RFC 5321, this implementation considers the following
     *                   commands to be valid (CRLF omitted):
     *                                                  VRFY john
     *                                                  VRFY "john"
     *                                                  VRFY "john@mail.com"
     *                                                  VRFY "John Doe"
     *                   Quoted strings may contain all printable ascii-characters (potentially with a backslash).
     *                   However, the RFC is quite fuzzy about nested quoted-strings (e.g. local-part quoted string
     *                   inside a quoted string). The validity of other mailboxes than defined above, will be solely
     *                   determined by the specific validation method used.
     */
    @Override
    public void parseArguments(SmtpVRFYCommand command, String parameter) {
        if (!isQuotedString(parameter)) {
            if (isWellFormedAtomStringUsername(parameter)) command.setUsername(parameter);
            else if (isValidMailbox(parameter)) command.setMailbox(parameter);
            else throwInvalidParameterException(); // TODO: check whether exception should be caught

            return;
        }

        // case: quoted string:
        parameter = parameter.substring(1, parameter.length() - 1); // strip outermost quotes
        if (isValidMailbox(parameter)) command.setMailbox(parameter);
        else if (isWellFormedQuotedStringUsername(parameter)) command.setUsername(parameter);
        else throwInvalidParameterException();
    }

    private void throwInvalidParameterException() {
        throw new IllegalArgumentException("The VRFY-command parameter is invalid: " +
                "it's neither a valid username nor a valid mailbox.");
    }

    private boolean isQuotedString(String string) {
        return string.length() > 1 &&
                string.charAt(0) == '"' &&
                string.charAt(string.length() - 1) == '"';
    }

    /**
     *
     * @param username Potential username provided in the VRFY-command.
     * @return Whether the username is RFC-5321 compliant, i.e. if it contains only regular characters or escaped
     *         special characters (backslash or double quote).
     */
    private boolean isWellFormedQuotedStringUsername(String username) {
        for (int i = 0; i < username.length(); i++) {
            int asciiValue = username.charAt(i);

            boolean isValid = asciiValue != 34 && asciiValue != 92; // i.e. not double quote or backslash
            boolean previousCharIsBackslash = i > 0 && ((int) username.charAt(i-1)) == 92; // backslash is used for escaping

            if (!isValid && !previousCharIsBackslash) return false;
        }

        return true;
    }

    private boolean isWellFormedAtomStringUsername(String username) {
        for (int i = 0; i < username.length(); i++) {
            if (!isValidAtomCharacter(username.charAt(i))) return false;
        }

        return true;
    }

    /**
     *
     * @param c Char of an atom string.
     * @return Whether it's valid according to RFC5322 (missing in RFC 5321).
     */
    private boolean isValidAtomCharacter(char c) {
        return c == 33 ||
                35 <= c && c <= 39 ||
                42 <= c && c <= 45 ||
                47 <= c && c <= 57 ||
                61 <= c && c <= 63 ||
                65 <= c && c <= 90 ||
                94 <= c && c <= 126;
    }

    /**
     * @param mailbox Mailbox address from the VRFY-command parameters.
     * @return Whether mailbox address has valid syntax in accordance with RFC822.
     * TODO: check whether RFC822 compliance is equivalent to RFC5321 compliance / how they differ.
     */
    private boolean isValidMailbox(String mailbox) {
        boolean isValid = true;

        try {
            InternetAddress internetAddress = new InternetAddress(mailbox);
            internetAddress.validate();
        } catch (AddressException ex) {
            isValid = false;
        }

        return isValid;
    }
}
