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
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import java.io.InputStream;
import java.util.List;

public class VRFYReplyParser extends SmtpReplyParser<SmtpVRFYReply> {

    private final String[] validStatusCodes =
            new String[] {"250", "251", "252", "502", "504", "550", "551", "553"};

    public VRFYReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(SmtpVRFYReply reply) {
        List<String> lines = parseAllLines();

        if (lines.isEmpty()) throw new ParserException("Malformed VRFY-Reply: Reply is empty.");

        reply.setStatusCode(parseStatusCode(lines.get(0), lines.size() == 1));

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            boolean isFinalLine = i == lines.size() - 1;
            String statusCode = parseStatusCode(line, isFinalLine);

            if (i > 0 && !reply.getStatusCode().equals(statusCode))
                throw new ParserException(
                        "Malformed VRFY-Reply: Multiline status codes are inconsistent.");

            if (i > 0 && isNormalResponse(statusCode) || isUnimplementedResponse(statusCode))
                throw new ParserException(
                        "Malformed VRFY-Reply: Normal response contains multiple lines.");

            line = line.substring(4).trim();
            parseResponse(statusCode, line, reply);
        }
    }

    private void parseResponse(String statusCode, String line, SmtpVRFYReply reply) {
        if (isNormalResponse(statusCode)) {
            boolean couldBeParsed = parseNormalResponse(line, reply, statusCode.equals("250"));

            if (!couldBeParsed)
                throw new ParserException(
                        "Malformed VRFY-Reply: Mailbox is invalid or reply may be malformed.");

            return;
        }

        if (isUnimplementedResponse(statusCode)) {
            parseUnimplementedResponse(line, reply);
            return;
        }

        parseAmbiguousAndUnavailableResponse(line, reply);
    }

    /**
     * Note: According to RFC5321, servers may either note the ambiguity or provide the ambiguous
     * mailboxes to the user. Since there is no fixed description that is to be used to note the
     * ambiguity, any string that doesn't contain a mailbox is considered to signify ambiguity. So
     * even if misused, the string will be saved in the reply's description property. We also make
     * the assumption that any ambiguity message will not contain an @ sign.
     *
     * @param line A string containing the text portion of a 553 (i.e. User ambiguous) or 550
     *     VRFY-Reply.
     * @param reply The SmtpVRFYReply object that data will be saved in.
     */
    private void parseAmbiguousAndUnavailableResponse(String line, SmtpVRFYReply reply) {
        boolean isAmbiguityMessage = !line.contains("@");

        if (isAmbiguityMessage) {
            trySettingDescription(line, reply);
            return;
        }

        boolean containsMailbox = parseNormalResponse(line, reply, true);

        if (!containsMailbox)
            throw new ParserException(
                    "Malformed VRFY-Reply: Mailbox is invalid or reply may be malformed.");
    }

    private void parseUnimplementedResponse(String line, SmtpVRFYReply reply) {
        reply.setDescription(line); // Line (i.e. description) can vary based on implementation.
    }

    private boolean isUnimplementedResponse(String statusCode) {
        switch (statusCode) {
            case "502":
            case "504":
                return true;
        }

        return false;
    }

    private boolean isNormalResponse(String statusCode) {
        switch (statusCode) {
            case "250":
            case "251":
            case "252":
            case "551":
                return true;
        }

        return false;
    }

    /**
     * Note: RFC5321's guidelines about the reply format are quite lax. While the RFC indicates that
     * hosts MAY decide to define the username as they want, we do not consider the use of quoted
     * strings here, as the unlimited use of double quotes or < in both username and local-part
     * would significantly complicate parsing. We *do* consider the general format that is used in
     * examples in the RFC.
     *
     * @param line A normal response line.
     * @param reply The SmtpVRFYReply object that data will be saved in.
     * @return Whether the response could be parsed, i.e. if it contains a valid mailbox.
     */
    private boolean parseNormalResponse(
            String line, SmtpVRFYReply reply, boolean mayContainFullName) {
        // case: single line local-part@domain without pointed brackets
        if (SmtpSyntaxParser.isValidMailbox(line)) {
            reply.addMailbox(line);
            return true;
        }

        // case: <local-part@domain> OR User Name <local-part@domain>
        int mailboxStartIndex = findMailboxStartIndex(line);
        String mailbox = line.substring(mailboxStartIndex + 1, line.length() - 1);

        if (!SmtpSyntaxParser.isValidMailbox(mailbox)) return false;

        reply.addMailbox(mailbox);
        if (mailboxStartIndex == 0) return true;

        String prefix = line.substring(0, mailboxStartIndex - 1); // everything before the mailbox
        if (mayContainFullName) reply.addFullName(prefix);
        else trySettingDescription(prefix, reply);

        return true;
    }

    private void trySettingDescription(String description, SmtpVRFYReply reply) {
        if (reply.getDescription() != null)
            throw new ParserException(
                    "Malformed VRFY-Reply: Reply may not contain multiple descriptions.");

        reply.setDescription(description);
    }

    /**
     * @param line A string that should contain a mailbox at the end.
     * @return The start index of the mailbox, i.e. the index of < in the string.
     */
    private int findMailboxStartIndex(String line) {
        // length < 5 because it needs to contain at least something of the form: <a@a>
        if (line.length() < 5)
            throw new ParserException("Malformed VRFY-Reply: Mailbox is too short.");

        if (line.charAt(line.length() - 1) != '>')
            throw new ParserException(
                    "Malformed VRFY-Reply: Mailbox is not enclosed in pointed brackets <>.");

        for (int i = line.length() - 1; i >= 0; i--) {
            if (line.charAt(i) == '<') return i;
        }

        throw new ParserException("Malformed VRFY-Reply: Mailbox is missing starting bracket <.");
    }

    private String parseStatusCode(String line, boolean isFinalLine) {
        String statusCode =
                SmtpSyntaxParser.startsWithValidStatusCode(line, validStatusCodes, isFinalLine);

        if (statusCode == null)
            throw new ParserException(
                    "Malformed VRFY-Reply: String starts with invalid status code or delimiter.");

        return statusCode;
    }
}
