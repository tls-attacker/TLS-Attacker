/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpRCPTReply;
import java.io.InputStream;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser to parse message into RCPT reply object, which contains the reply code and message.
 * If the reply message does not follow that syntax, the validReply parameter is set to False.
 */
public class RCPTReplyParser extends SmtpReplyParser<SmtpRCPTReply> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RCPTReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpRCPTReply smtpRCPTReply) {
        LOGGER.trace("Parsing RCPTReply");
        List<String> lines = readWholeReply();
        LOGGER.trace("Parsing lines: {}", lines);

        if (lines.isEmpty()) {
            LOGGER.trace("Reply is empty");
//            smtpRCPTReply.setValidReply(false);
            return;
        }

        // parse reply code, which should be the first 3 digits
        int replyCode = 0;
        try {
            replyCode = Integer.parseInt(lines.get(0).substring(0, 3));
        } catch (NumberFormatException e) {
            LOGGER.trace("Could not parse RCPTReply code: {}", e.getMessage());
//            smtpRCPTReply.setValidReply(false);
            return;
        }

        smtpRCPTReply.setReplyCode(replyCode);

        // all valid codes
        Integer[] successCodes = {250, 251};
        Integer[] errorCodes = {550, 551, 552, 553, 450, 451, 452, 503, 455, 555};

        if (List.of(successCodes).contains(replyCode)) {
//            smtpRCPTReply.setValidReply(true);
            LOGGER.trace("RCPTReply fine. {}", lines);
        } else if (List.of(errorCodes).contains(replyCode)) {
//            smtpRCPTReply.setValidReply(true);
            LOGGER.trace("Error code in RCPTReply. {}", lines);
        } else {
//            smtpRCPTReply.setValidReply(false);
            LOGGER.trace("Could not parse RCPTReply. {}", lines);
        }
    }
}
