package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpHELPReply;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.util.List;

/**
 * Parser to parse message into HELP reply object, which contains the reply code and message.
 * If the reply message does not follow that syntax, the validReply parameter is set to False.
 * HELP replies can be single or multi-line.
 */
public class HELPReplyParser extends SmtpReplyParser<SmtpHELPReply> {
    private static final Logger LOGGER = LogManager.getLogger();

    public HELPReplyParser(InputStream stream) {
        super(stream);
    }

    public boolean isMultilineReply(List<String> lines) {
        return lines.get(0).substring(3,4).equals("-");
    }

    @Override
    public void parse(SmtpHELPReply smtpHELPReply) {
        List<String> lines = readWholeReply();
        int replyCode = Integer.parseInt(lines.get(0).substring(0, 3));
        smtpHELPReply.setReplyCode(replyCode);
        smtpHELPReply.setReplyLines(lines);
        smtpHELPReply.setValidReply(true);

        if (isMultilineReply(lines))
        {
            // multiline response
            for (String line : lines) {
                int replyCodeLine = Integer.parseInt(line.substring(0, 3));
                if (replyCode != replyCodeLine) {
                    LOGGER.warn(
                            "Parsing HELP Reply found inconsistent status codes in multiline reply {} != {}",
                            replyCode,
                            replyCodeLine);
                    smtpHELPReply.setValidReply(false);
                }
            }
        }

        Integer[] successCodes = {211, 214};
        Integer[] errorCodes = {502, 504};

        smtpHELPReply.setHelpMessage(String.join("", lines));

        if (List.of(successCodes).contains(replyCode)){
            LOGGER.trace("Success code in HELPReply. {}", lines);
        } else if (List.of(errorCodes).contains(replyCode)) {
            LOGGER.trace("Error code in HELPReply. {}", lines);
        } else {
            smtpHELPReply.setValidReply(false);
            LOGGER.trace("Could not parse HELPReply. {}", lines);
        }
    }
}
