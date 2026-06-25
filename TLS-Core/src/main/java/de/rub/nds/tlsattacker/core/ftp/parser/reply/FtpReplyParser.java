/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.parser.reply;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.ftp.parser.FtpMessageParser;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses FtpReplies from an InputStream. The default implementation parses the status code and the
 * human-readable message. The format for multiline replies requires that every line, except the
 * last, begins with the reply code followed immediately by a hyphen ("{@code NNN-}"). The last line
 * begins with the reply code followed by a space ("{@code NNN }"). In a multiline reply the reply
 * code on each line MUST be the same (RFC 959).
 *
 * @param <ReplyT> specific reply class
 */
public abstract class FtpReplyParser<ReplyT extends FtpReply> extends FtpMessageParser<ReplyT> {

    public FtpReplyParser(InputStream stream) {
        super(stream);
    }

    /**
     * Reads the whole reply from the input stream. The reply is terminated by a line with the reply
     * code, a space, and a message. A ParserException is thrown if a non-terminating line is not a
     * valid multiline continuation.
     *
     * @return all lines of the reply
     */
    public List<String> readWholeReply() {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = parseSingleLine()) != null) {
            lines.add(line);
            if (isEndOfReply(line)) {
                break;
            }
            if (!isPartOfMultilineReply(line)) {
                throw new ParserException("Expected multiline reply but got: " + line);
            }
        }
        return lines;
    }

    public void parseReplyCode(ReplyT reply, String line) {
        if (line.length() < 3) {
            return;
        }
        int replyCode = this.toInteger(line.substring(0, 3));
        reply.setReplyCode(replyCode);
    }

    public int toInteger(String str) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException ex) {
            throw new ParserException(
                    "Could not parse FtpReply. Could not parse reply code: " + str);
        }
    }

    public boolean isPartOfMultilineReply(String line) {
        return line.matches("\\d{3}-.*");
    }

    public boolean isEndOfReply(String line) {
        return line.matches("\\d{3} .*") || line.matches("\\d{3}");
    }
}
