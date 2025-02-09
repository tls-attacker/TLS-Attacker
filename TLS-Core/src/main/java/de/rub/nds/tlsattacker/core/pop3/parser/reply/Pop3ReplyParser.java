/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import java.io.*;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parses Pop3 replies from InputStream. The default implementation only parses the status code and
 * the human readable message. If more complex parsing is needed, the parse method can be
 * overridden. Multiline replies begin with the status indicator in the first line and every line
 * terminated with <CRLF> the last line is just a . followed by <CRLF>. The response is ended by
 * encountering following sequence: <CRLF>.<CRLF>
 *
 * @param <ReplyT> specific reply class
 */
public abstract class Pop3ReplyParser<ReplyT extends Pop3Reply> extends Pop3MessageParser<ReplyT> {

    public Pop3ReplyParser(InputStream stream) {
        super(stream);
    }

    public void parseHumanReadableMessage(ReplyT reply, String line) {
        String humanReadableMessage = "";

        if (line.startsWith("+OK") & line.length() > 3) humanReadableMessage = line.substring(4);
        else if (line.startsWith("-ERR") & line.length() > 4)
            humanReadableMessage = line.substring(5);

        reply.setHumanReadableMessage(humanReadableMessage);
    }

    /**
     * This function is the default parsing function when it's uncertain whether the reply is single
     * or multiline. It will process the first line of a reply and store reply indicator and
     * human-readable message in the reply class. To detect whether the reply is multiline, it will
     * call tryParseMultiline() which reads from the stream until it is empty. If the stream is
     * empty right away, it signifies that the reply is single-line. If not, it will return the
     * remaining lines until the stream is empty. These lines are returned for further parsing in
     * the specific reply parsers.
     *
     * @param reply Any pop3 reply class.
     * @return All lines except for the first. Will return an empty list if the reply is
     *     single-line.
     */
    public List<String> parseReply(ReplyT reply) {
        parseSingleLineReply(reply);
        return tryParseMultiLines();
    }

    public void parseSingleLineReply(ReplyT reply) {
        String firstLine = parseSingleLine();
        parseReplyIndicator(reply, firstLine);
        parseHumanReadableMessage(reply, firstLine);
    }

    public List<String> tryParseMultiLines() {
        List<String> lines = new LinkedList<>();
        try (BufferedInputStream stream = new BufferedInputStream(this.getStream())) {
            String line = "";
            char LF = 10;
            char CR = 13;
            while (!line.equals(".")) { // multiline replies have to end with ".CRLF" i.e. ".\r\n"
                StringBuilder sb = new StringBuilder();
                int c = stream.read();
                if (c == -1) break; // stream is empty

                while (c != LF) { // while end of line is not reached
                    sb.append((char) c);
                    c = stream.read();
                }

                if (sb.charAt(sb.length() - 1) != CR)
                    LOGGER.warn(
                            "Reply must be terminated with CRLF but is only terminated with LF.");

                sb.setLength(sb.length() - 1); // remove CR

                line = sb.toString();
                if (!line.equals("."))
                    lines.add(line); // no need to save "." because it's no actual content
            }
        } catch (IOException ignored) {
            LOGGER.warn(
                    "An IOException occurred while checking for multi-line replies. This is normal behavior if the reply was single-line. If not, the reply is likely malformed.");
        }

        return lines;
    }

    public void parseReplyIndicator(ReplyT reply, String line) {
        if (line.matches("^\\+OK.*")) {
            reply.setStatusIndicator("+OK");
        } else if (line.matches("^-ERR.*")) {
            reply.setStatusIndicator("-ERR");
        } else {
            reply.setStatusIndicator("");
        }
    }

    public int toInteger(String str) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException ex) {
            throw new ParserException(
                    "Could not parse pop3-reply message data. Could not parse: " + str);
        }
    }

    public abstract void parse(ReplyT reply);
}
