package de.rub.nds.tlsattacker.core.smtp.parser;

import org.bouncycastle.util.IPAddress;

/**
 * This class contains functions that check syntax based on RFC5321's Command Argument Syntax.
 */
public final class SyntaxChecker {
    public static boolean isNotAQuotedString(String string) {
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
    public static boolean isValidQuotedStringContent(String str) {
        for (int i = 0; i < str.length(); i++) {
            int asciiValue = str.charAt(i);

            boolean isValid = asciiValue != 34 && asciiValue != 92; // i.e. not double quote or backslash
            boolean isEscaped = i > 0 && ((int) str.charAt(i-1)) == 92; // backslash is used for escaping

            if (!isValid && !isEscaped) return false;
        }

        return true;
    }

    public static boolean isValidAtomString(String str) {
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
    private static boolean isNotAnAtomCharacter(char c) {
        return !(c == 33 ||
                35 <= c && c <= 39 ||
                42 <= c && c <= 45 ||
                47 <= c && c <= 57 ||
                61 <= c && c <= 63 ||
                65 <= c && c <= 90 ||
                94 <= c && c <= 126);
    }

    private static boolean isNotAlphanumeric(char c) {
        return !(48 <= c && c <= 57 ||
                65 <= c && c <= 90 ||
                97 <= c && c <= 122);
    }

    private static boolean isValidDotString(String str) {
        // first and last character must be atom characters
        if (isNotAnAtomCharacter(str.charAt(0)) || isNotAnAtomCharacter(str.charAt(str.length()-1))) return false;

        for (int i = 1; i < str.length()-1; i++) {
            char c = str.charAt(i);
            if (isNotAnAtomCharacter(c) && c != '.') return false;
        }

        return true;
    }

    private static int endIndexOfLocalPart(String mailbox) {
        for (int i = mailbox.length()-1; i >= 0; i--) { // Last '@'-sign denotes ending of local-part.
            if (mailbox.charAt(i) != '@') continue;
            return i;
        }

        throw new IllegalArgumentException("Malformed VRFY-command: mailbox doesn't contain an '@'-sign.");
    }

    private static boolean isValidSubdomain(String str) {
        // first and last characters have to be alphanumeric:
        if (isNotAlphanumeric(str.charAt(0)) || isNotAlphanumeric(str.charAt(str.length()-1))) return false;

        // characters in between may also be '-'
        for (int i = 1; i < str.length()-1; i++) {
            char c = str.charAt(i);
            if (isNotAlphanumeric(c) && c != '-') return false;
        }

        return true;
    }

    private static boolean isValidDomain(String str) {
        String[] subdomains = str.split("\\."); // if this causes issues use Pattern.quote(".") instead

        for (String subdomain : subdomains) {
            if (!isValidSubdomain(subdomain)) return false;
        }

        return true;
    }

    private static boolean isValidAddressLiteral(String str) {
        return IPAddress.isValid(str);
    }

    private static boolean isValidLocalPart(String localPart) {
        if (localPart.isEmpty()) return false;

        if (isValidDotString(localPart)) return true;

        // case: special characters were found, thus local part must be quoted string:
        if (localPart.charAt(0) != '"' || localPart.charAt(localPart.length()-1) != '"') return false;

        localPart = localPart.substring(1, localPart.length()-1); // strip double quotes

        return isValidQuotedStringContent(localPart);
    }

    /**
     * @param mailbox String potentially containing a mailbox.
     * @return Whether mailbox address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidMailbox(String mailbox) {
        String localPart = mailbox.substring(0, endIndexOfLocalPart(mailbox));

        if (!isValidLocalPart(localPart))
            throw new IllegalArgumentException("Malformed VRFY-command: local-part is invalid.");

        String mailboxEnding = mailbox.substring(endIndexOfLocalPart(mailbox)+1); // everything past @
        if (isValidAddressLiteral(mailboxEnding) || isValidDomain(mailboxEnding)) return true;

        throw new IllegalArgumentException("Malformed VRFY-command: mailbox domain/address-literal is invalid.");
    }
}
