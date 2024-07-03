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
     * @param str The content of a quoted string (i.e. with outermost double quotes already removed).
     * @return Whether the content is RFC-5321 compliant, i.e. if it contains only regular characters or escaped
     *         special characters (backslash or double quote).
     */
    public static boolean isValidQuotedStringContent(String str) {
        return doesNotContainControlCharacters(str);
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

        return -1;
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
        if (str.charAt(0) != '[' || str.charAt(str.length()-1) != ']') return false;

        return IPAddress.isValid(str.substring(1, str.length()-1));
    }

    private static boolean doesNotContainControlCharacters(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) < 32) return false;
        }

        return true;
    }

    private static boolean isValidLocalPart(String localPart) {
        if (localPart.isEmpty()) return false;

        if (isValidDotString(localPart)) return true;

        // case: special characters were found, thus local part must be quoted string:
        if (localPart.charAt(0) != '"' || localPart.charAt(localPart.length()-1) != '"') return false;

        // if localPart is encompassed by double quotes, any character is permitted
        return true;
    }

    /**
     * @param mailbox String potentially containing a mailbox.
     * @return Whether mailbox address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidMailbox(String mailbox) {
        String localPart = mailbox.substring(0, endIndexOfLocalPart(mailbox));

        if (!isValidLocalPart(localPart)) return false;

        String mailboxEnding = mailbox.substring(endIndexOfLocalPart(mailbox)+1); // everything past @

        return isValidAddressLiteral(mailboxEnding) || isValidDomain(mailboxEnding);
    }
}
