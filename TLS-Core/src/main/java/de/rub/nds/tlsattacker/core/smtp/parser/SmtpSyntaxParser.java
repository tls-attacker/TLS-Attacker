/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import org.bouncycastle.util.IPAddress;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** This class contains functions that check syntax based on RFC5321's Command Argument Syntax. */
public final class SmtpSyntaxParser {
    /**
     * @param string Any string.
     * @return Whether the string is a quoted string. Note: Does not check quoted string content.
     */
    public static boolean isNotAQuotedString(String string) {
        return !(string.length() > 1
                && string.charAt(0) == '"'
                && string.charAt(string.length() - 1) == '"');
    }

    /**
     * @param str The content of a quoted string (i.e. with outermost double quotes already
     *     removed).
     * @return Whether the content is RFC-5321 compliant, i.e. if it contains only regular
     *     characters or escaped special characters (backslash or double quote).
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
     * @param c Any character.
     * @return Whether it's invalid according to RFC5322 (definition missing in RFC 5321).
     */
    private static boolean isNotAnAtomCharacter(char c) {
        return !(c == 33
                || 35 <= c && c <= 39
                || 42 <= c && c <= 45
                || 47 <= c && c <= 57
                || 61 <= c && c <= 63
                || 65 <= c && c <= 90
                || 94 <= c && c <= 126);
    }

    private static boolean isNotAlphanumeric(char c) {
        return !(48 <= c && c <= 57 || 65 <= c && c <= 90 || 97 <= c && c <= 122);
    }

    private static boolean isValidDotString(String str) {
        // first and last character must be atom characters
        if (isNotAnAtomCharacter(str.charAt(0))
                || isNotAnAtomCharacter(str.charAt(str.length() - 1))) return false;

        for (int i = 1; i < str.length() - 1; i++) {
            char c = str.charAt(i);
            if (isNotAnAtomCharacter(c) && c != '.') return false;
            if (str.charAt(i - 1) == '.' && c == '.')
                return false; // consecutive dots are not allowed
        }

        return true;
    }

    private static int endIndexOfLocalPart(String mailbox) {
        for (int i = mailbox.length() - 1; i >= 0; i--) {
            if (mailbox.charAt(i) != '@') continue;
            return i;
        }
        return 0;
    }

    private static boolean isValidSubdomain(String str) {
        // first and last characters have to be alphanumeric:
        if (str.isEmpty()
                || isNotAlphanumeric(str.charAt(0))
                || isNotAlphanumeric(str.charAt(str.length() - 1))) return false;

        // characters in between may also be '-'
        for (int i = 1; i < str.length() - 1; i++) {
            char c = str.charAt(i);
            if (isNotAlphanumeric(c) && c != '-') return false;
        }
        return true;
    }

    private static boolean isValidDomain(String str) {
        String[] subdomains = str.split("\\.");

        for (String subdomain : subdomains) {
            if (!isValidSubdomain(subdomain)) return false;
        }
        return true;
    }

    private static boolean isValidAtDomain(String str) {
        return str.startsWith("@") && isValidDomain(str.substring(1));
    }

    private static boolean isValidAddressLiteral(String str) {
        if (str.isEmpty() || str.charAt(0) != '[' || str.charAt(str.length() - 1) != ']')
            return false;

        if (str.startsWith("[IPv6:")) str = str.substring(6, str.length() - 1);
        else str = str.substring(1, str.length() - 1);

        return IPAddress.isValid(str);
    }

    private static boolean doesNotContainControlCharacters(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) < 32) return false;
        }

        return true;
    }

    /**
     * @param hopString String potentially containing hops / @-domains.
     * @return Whether address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidHopString(String hopString) {
        if (hopString.contains(","))
        {
            // contains several domains, so check them all
            String[] hops = hopString.split(",");
            for (String hop : hops) {
                if (!isValidAtDomain(hop)) return false;
            }
            return true;
        }
        else{
            return isValidDomain(hopString);
        }
    }

    private static boolean isValidLocalPart(String localPart) {
        if (localPart.isEmpty()) return false;
        if (isValidDotString(localPart)) return true;

        // case: special characters were found, thus local part must be quoted string:
        return localPart.charAt(0) == '"'
                && localPart.charAt(localPart.length() - 1) == '"'
                && SmtpSyntaxParser.isValidQuotedStringContent(
                localPart.substring(1, localPart.length() - 1));
    }

    /**
     * @param postmaster String potentially containing a postmaster.
     * @return Whether address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidPostmaster(String postmaster) {
        String localPart = postmaster.substring(0, endIndexOfLocalPart(postmaster));

        return postmaster.equalsIgnoreCase("postmaster");
        }

    /**
     * @param forwardPath String potentially containing a forward path.
     * @return Whether address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidForwardPath(String forwardPath) {
        if (forwardPath.contains(":"))
        {
            String hopString = forwardPath.substring(0, forwardPath.indexOf(":"));
            String mailbox = forwardPath.substring(forwardPath.indexOf(":") + 1);

            return isValidHopString(hopString) && isValidMailbox(mailbox);
        }
        return false;
    }

    /**
     * @param address String potentially containing a IP address.
     * @return Whether address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidIPAddress(String address) {
        // regular expression for IP addresses
        String regex = "^[a-zA-Z0-9._%+-]+@\\[(IPv6:[a-fA-F0-9:]+|\\d{1,3}(?:\\.\\d{1,3}){3})\\]$";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(address);

        return matcher.matches();
       }

    /**
     * @param mailbox String potentially containing a mailbox.
     * @return Whether mailbox address has valid syntax in accordance with RFC5321.
     */
    public static boolean isValidMailbox(String mailbox) {
        String localPart = mailbox.substring(0, endIndexOfLocalPart(mailbox));

        if (!isValidLocalPart(localPart)) return false;

        String mailboxEnding =
                mailbox.substring(endIndexOfLocalPart(mailbox) + 1); // everything past @

        return isValidAddressLiteral(mailboxEnding) || isValidDomain(mailboxEnding);
    }

    public static int startsWithValidReplyCode(
            String reply, int[] validReplyCodes, boolean isFinalLine) {
        char delimiter = ' ';
        if (!isFinalLine) delimiter = '-';

        for (int code : validReplyCodes) {
            if (reply.startsWith(String.valueOf(code) + delimiter)) return code;
        }

        return -1;
    }
}