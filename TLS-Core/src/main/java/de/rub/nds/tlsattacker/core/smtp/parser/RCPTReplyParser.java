package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpRCPTReply;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.util.List;

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

        if(lines.isEmpty()){
            LOGGER.trace("Reply is empty");
            smtpRCPTReply.setValid(false);
            return;
        }

        // parse into reply message object
        int replyCode = 0;
        try{
            replyCode = Integer.parseInt(lines.get(0).substring(0, 3));
        }
        catch(NumberFormatException e){
            LOGGER.trace("Could not parse RCPTReply code: {}", e.getMessage());
            smtpRCPTReply.setValid(false);
            return;
        }

        smtpRCPTReply.setReplyCode(replyCode);
        smtpRCPTReply.setReplyLines(lines);

        // all valid codes
        Integer[] validCodes = {250, 251};
        Integer[] errorCodes = {550, 551, 552, 553, 450, 451, 452, 503, 455, 555};

        if (List.of(validCodes).contains(replyCode)) {
            smtpRCPTReply.setValid(true);
            LOGGER.trace("RCPTReply fine. {}", lines);
        }
        else if (List.of(errorCodes).contains(replyCode)) {
            smtpRCPTReply.setValid(true);
            LOGGER.trace(
                    "Error code in RCPTReply. {}", lines);
        }
        else {
            smtpRCPTReply.setValid(false);
            LOGGER.trace(
                    "Could not parse RCPTReply. {}", lines);
        }
    }
}    