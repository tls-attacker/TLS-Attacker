/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.util.IPAddress;

/** This class contains functions that check syntax based on RFC5321's Command Argument Syntax. */
public final class SmtpSyntaxParser {
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
        for (int i = mailbox.length() - 1;
                i >= 0;
                i--) { // Last '@'-sign denotes ending of local-part.
            if (mailbox.charAt(i) != '@') continue;
            return i;
        }

        // TODO: consider changing:
        return 0; // For now, it sets an invalid index to 0, so isValidLocalPart() detects that the
        // local-part is empty.
    }

    private static boolean isValidSubdomain(String str) {
        // first and last characters have to be alphanumeric:
        if (isNotAlphanumeric(str.charAt(0)) || isNotAlphanumeric(str.charAt(str.length() - 1)))
            return false;

        // characters in between may also be '-'
        for (int i = 1; i < str.length() - 1; i++) {
            char c = str.charAt(i);
            if (isNotAlphanumeric(c) && c != '-') return false;
        }

        return true;
    }

    private static boolean isValidDomain(String str) {
        String[] subdomains =
                str.split("\\."); // if this causes issues use Pattern.quote(".") instead

        for (String subdomain : subdomains) {
            if (!isValidSubdomain(subdomain)) return false;
        }

        return true;
    }

    private static boolean isValidAddressLiteral(String str) {
        if (str.charAt(0) != '[' || str.charAt(str.length() - 1) != ']') return false;

        str =
                str.startsWith("[IPv6:")
                        ? str.substring(6, str.length() - 1)
                        : str.substring(1, str.length() - 1);

        return IPAddress.isValid(str);
    }

    private static boolean doesNotContainControlCharacters(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) < 32) return false;
        }

        return true;
    }

    private static boolean isValidLocalPart(String localPart) {
        if (localPart.isEmpty()) return false;
        if (localPart.getBytes(StandardCharsets.UTF_8).length > 64)
            return false; // can't be longer than 64 octets

        if (isValidDotString(localPart)) return true;

        // case: special characters were found, thus local part must be quoted string:
        return localPart.charAt(0) == '"' && localPart.charAt(localPart.length() - 1) == '"';
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

    private static boolean isValidesmtpKeyword(String keyword) {
        if (isNotAlphanumeric(keyword.charAt(0))) {
            return false;
        }
        for (int i = 0; i < keyword.length(); i++) {
            char c = keyword.charAt(i);
            if (isNotAlphanumeric(c) && c != '-') {
                return false;
            }
        }
        return true;
    }

    private static boolean isValidesmtpValue(String value) {
        return value != null && value.matches("^[\\x21-\\x3C\\x3E-\\x7E]+$");
    }

    public static boolean isValidSpecialParameter(String[] parameter) {
        if (parameter.length < 2) {
            return false;
        }
        if (!parameter[1].startsWith("[\"=\"") || !parameter[1].endsWith("]")) {
            return false;
        }
        parameter[1] = parameter[1].replaceAll("[\\[\\]]", "");
        parameter[1] = parameter[1].replace("\"=\"", "");
        return (isValidesmtpKeyword(parameter[0]) && isValidesmtpValue(parameter[1]));
    }

    public static SmtpServiceExtension parseKeyword(String ext, String parameters) {
        // just ehlo-line
        switch (ext) {
            case "8BITMIME":
                return new _8BITMIMEExtension();
            case "ATRN":
                return new ATRNExtension();
            case "AUTH":
                String[] sasl = parameters.split(" ");
                return new AUTHExtension(new ArrayList<>(List.of(sasl)));
            case "BINARYMIME":
                return new BINARYMIMEExtension();
            case "BURL":
                // TODO: BURL parameter not understood in any way
                return new BURLExtension(parameters);
            case "CHECKPOINT":
                return new CHECKPOINTExtension();
            case "CHUNKING":
                return new CHUNKINGExtension();
            case "CONNEG":
                return new CONNEGExtension();
            case "CONPERM":
                return new CONPERMExtension();
            case "DELIVERBY":
                return new DELIVERBYExtension();
            case "DSN":
                return new DSNExtension();
            case "ENHANCEDSTATUSCODES":
                return new ENHANCEDSTATUSCODESExtension();
            case "ETRN":
                return new ETRNExtension();
            case "EXPN":
                return new EXPNExtension();
            case "FUTURERELEASE":
                return new FUTURERELEASEExtension();
            case "HELP":
                return new HELPExtension();
            case "LIMITS":
                return new LIMITSExtension();
            case "MT-PRIORITY":
                // TODO: MT_PRIORITY parameter not understood in any way
                return new MT_PRIORITYExtension(parameters);
            case "MTRK":
                return new MTRKExtension();
            case "NO-SOLICITING":
                // TODO: NO-SOLICITING parameter not understood in any way
                return new NO_SOLICITINGExtension(parameters);
            case "PIPELINING":
                return new PIPELININGExtension();
            case "REQUIRETLS":
                return new REQUIRETLSExtension();
            case "RRVS":
                return new RRVSExtension();
            case "SAML":
                return new SAMLExtension();
            case "SEND":
                return new SENDExtension();
            case "SIZE":
                // TODO: SIZE can have a parameter
                int size = Integer.parseInt(parameters);
                return new SIZEExtension(size);
            case "SMTPUTF8":
                return new SMTPUTF8Extension();
            case "SOML":
                return new SOMLExtension();
            case "STARTTLS":
                return new STARTTLSExtension();
            case "SUBMITTER":
                return new SUBMITTERExtension();
            case "TURN":
                return new TURNExtension();
            case "UTF8SMTP":
                return new UTF8SMTPExtension();
            case "VERB":
                return new VERBExtension();
            default:
                if (ext.startsWith("X") || ext.startsWith("x")) {
                    return new LocalSmtpServiceExtension(ext, parameters);
                } else {
                    throw new ParserException(
                            "Could not parse Extension of Command/Reply. Unknown keyword: " + ext);
                }
        }
    }
}
