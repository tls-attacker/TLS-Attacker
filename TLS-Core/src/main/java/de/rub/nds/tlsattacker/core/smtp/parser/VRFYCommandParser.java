package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import org.bouncycastle.util.IPAddress;

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
        if (isNotAQuotedString(parameter)) {
            if (isValidAtomString(parameter)) command.setUsername(parameter);
            else if (isValidMailbox(parameter)) command.setMailbox(parameter);
            else throwInvalidParameterException(); // TODO: check whether exception should be caught

            return;
        }

        // case: quoted string:
        parameter = parameter.substring(1, parameter.length() - 1); // strip outermost quotes
        if (isValidMailbox(parameter)) command.setMailbox(parameter);
        else if (isValidQuotedStringContent(parameter)) command.setUsername(parameter);
        else throwInvalidParameterException();
    }

    private void throwInvalidParameterException() {
        throw new IllegalArgumentException("The VRFY-command parameter is invalid: " +
                "it's neither a valid username nor a valid mailbox.");
    }

    private boolean isNotAQuotedString(String string) {
        return !(string.length() > 1 &&
                string.charAt(0) == '"' &&
                string.charAt(string.length() - 1) == '"');
    }

    /**
     *
     * @param str The content of a quoted string.
     * @return Whether the content is RFC-5321 compliant, i.e. if it contains only regular characters or escaped
     *         special characters (backslash or double quote).
     */
    private boolean isValidQuotedStringContent(String str) {
        for (int i = 0; i < str.length(); i++) {
            int asciiValue = str.charAt(i);

            boolean isValid = asciiValue != 34 && asciiValue != 92; // i.e. not double quote or backslash
            boolean isEscaped = i > 0 && ((int) str.charAt(i-1)) == 92; // backslash is used for escaping

            if (!isValid && !isEscaped) return false;
        }

        return true;
    }

    private boolean isValidAtomString(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (isNotAnAtomCharacter(str.charAt(i))) return false;
        }

        return true;
    }

    /**
     *
     * @param c Any character.
     * @return Whether it's invalid according to RFC5322 (definition missing in RFC 5321).
     */
    private boolean isNotAnAtomCharacter(char c) {
        return !(c == 33 ||
                35 <= c && c <= 39 ||
                42 <= c && c <= 45 ||
                47 <= c && c <= 57 ||
                61 <= c && c <= 63 ||
                65 <= c && c <= 90 ||
                94 <= c && c <= 126);
    }

    private boolean isNotAlphanumeric(char c) {
        return !(48 <= c && c <= 57 ||
                65 <= c && c <= 90 ||
                97 <= c && c <= 122);
    }

    private boolean isValidDotString(String str) {
        if (isNotAnAtomCharacter(str.charAt(0))) return false;

        for (int i = 1; i < str.length(); i++) {
            char c = str.charAt(i);
            if (isNotAnAtomCharacter(c) && c != '.') return false;
        }

        return true;
    }

    private int endIndexOfLocalPart(String mailbox) {
        for (int i = mailbox.length()-1; i >= 0; i--) { // Last '@'-sign denotes ending of local-part.
            if (mailbox.charAt(i) != '@') continue;
            return i;
        }

        throw new IllegalArgumentException("Malformed VRFY-command: mailbox doesn't contain an '@'-sign.");
    }

    private boolean isValidSubdomain(String str) {
        // first and last characters have to be alphanumeric:
        if (isNotAlphanumeric(str.charAt(0)) || isNotAlphanumeric(str.charAt(str.length()-1))) return false;

        // characters in between may also be '-'
        for (int i = 1; i < str.length()-1; i++) {
            char c = str.charAt(i);
            if (isNotAlphanumeric(c) && c != '-') return false;
        }

        return true;
    }

    private boolean isValidDomain(String str) {
        String[] subdomains = str.split("\\."); // if this causes issues use Pattern.quote(".") instead

        for (String subdomain : subdomains) {
            if (!isValidSubdomain(subdomain)) return false;
        }

        return true;
    }

    private boolean isValidAddressLiteral(String str) {
        return IPAddress.isValid(str);
    }

    private boolean isValidLocalPart(String localPart) {
        if (localPart.isEmpty()) return false;

        if (isValidDotString(localPart)) return true; // note: method is equivalent for local part

        // case: special characters were found, thus local part must be quoted string:
        if (localPart.charAt(0) != '"' || localPart.charAt(localPart.length()-1) != '"') return false;

        localPart = localPart.substring(1, localPart.length()-1); // strip double quotes

        return isValidQuotedStringContent(localPart);
    }

    /**
     * @param mailbox Mailbox address from the VRFY-command parameters.
     * @return Whether mailbox address has valid syntax in accordance with RFC5321.
     */
    private boolean isValidMailbox(String mailbox) {
        if (isNotAQuotedString(mailbox)) // the mailbox must be a quoted-string because of the '@'-sign
            throw new IllegalArgumentException("Malformed VRFY-command: mailbox must be a quoted-string");

        mailbox = mailbox.substring(1, mailbox.length()-1); // strip outermost double quotes
        String localPart = mailbox.substring(0, endIndexOfLocalPart(mailbox));

        if (!isValidLocalPart(localPart))
            throw new IllegalArgumentException("Malformed VRFY-command: local-part is invalid.");

        String mailboxEnding = mailbox.substring(endIndexOfLocalPart(mailbox)+1); // everything past @
        if (isValidAddressLiteral(mailboxEnding) || isValidDomain(mailboxEnding)) return true;

        throw new IllegalArgumentException("Malformed VRFY-command: mailbox domain/address-literal is invalid.");
    }
}
