/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parses SmtpReplies from an InputStream. The default implementation only parses the status code
 * and the human readable message. If more complex parsing is needed, the parseMessage method can be
 * overridden. Assumption: - The format for multiline replies requires that every line, except the
 * last, begin with the reply code, followed immediately by a hyphen, "-" (also known as minus),
 * followed by text. The last line will begin with the reply code, followed immediately by
 * &lt;SP&gt;, optionally some text, and &lt;CRLF&gt;. - In a multiline reply, the reply code on
 * each of the lines MUST be the same.
 *
 * @param <ReplyT>
 */
public abstract class SmtpReplyParser<ReplyT extends SmtpReply> extends SmtpMessageParser<ReplyT> {
    private static final Logger LOGGER = LogManager.getLogger();

    public SmtpReplyParser(InputStream stream) {
        super(stream);
    }

    /**
     * Reads the whole reply from the input stream. The reply is terminated by a line with Status
     * code space and message. If a reply does not fulfill this condition, a ParserException is
     * thrown. TODO: That means lines are lost if the reply is not terminated by a line with Status
     * code space and message. TODO: make sure that classes calling this are aware
     *
     * @return
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

    public void parseReplyCode(ReplyT replyT, String line) {
        if (line.length() < 3) return;

        int replyCode = this.toInteger(line.substring(0, 3));

        // warning if status code is already set but codes are inconsistent:
        try {
            if (replyT.getReplyCode() != replyCode) replyCodeWarning(replyCode, line);
        } catch (NullPointerException ignored) {
        } // case: reply code not initialized yet

        replyT.setReplyCode(replyCode);
    }

    public void checkReplyCodeConsistency(int replyCode, String replyCodeString) {
        int foundReplyCode = this.toInteger(replyCodeString);
        if (foundReplyCode != replyCode) {
            replyCodeWarning(replyCode, replyCodeString);
        }
    }

    public void replyCodeWarning(int replyCode, String replyCodeString) {
        LOGGER.warn(
                "Parsing EHLOReply found inconsistent status codes in multiline reply{} != {}",
                replyCode,
                replyCodeString);
    }

    public int toInteger(String str) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException ex) {
            throw new ParserException(
                    "Could not parse SmtpReply. Could not parse reply code:" + str);
        }
    }

    public boolean isPartOfMultilineReply(String line) {
        return line.matches("\\d{3}-.*");
    }

    public boolean isEndOfReply(String line) {
        return line.matches("\\d{3} .*");
    }
}
