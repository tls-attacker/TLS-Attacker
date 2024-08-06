package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpHELPReply;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.util.List;

public class HELPReplyParser extends SmtpReplyParser<SmtpHELPReply> {
    private static final Logger LOGGER = LogManager.getLogger();

    public HELPReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpHELPReply smtpHELPReply) {
        super.parse(smtpHELPReply);

        Integer[] successCodes = {211, 214};
        Integer[] errorCodes = {502, 504};
        int replyCode = smtpHELPReply.getReplyCode();
        List<String> lines = smtpHELPReply.getReplyLines();

        smtpHELPReply.setHelpMessage(String.join("", lines));

        if (List.of(successCodes).contains(replyCode)){
            smtpHELPReply.setValidReply(true);
            LOGGER.trace("Success code in HELPReply. {}", lines);
        } else if (List.of(errorCodes).contains(replyCode)) {
            smtpHELPReply.setValidReply(true);
            LOGGER.trace("Error code in HELPReply. {}", lines);
        } else {
            smtpHELPReply.setValidReply(false);
            LOGGER.trace("Could not parse HELPReply. {}", lines);
        }
    }
}
