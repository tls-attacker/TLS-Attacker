package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAContentReply;


import java.io.InputStream;
import java.util.Arrays;
import java.util.List;


public class DATAContentReplyParser extends SmtpReplyParser<SmtpDATAContentReply>{

    public DATAContentReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAContentReply dataReply) {
        List<String> lines = parseAllLines();
        // save all possible reply codes
        List<String> replyCodes =
                Arrays.asList(
                        "250", "552", "554", "451", "452", "450", "550");
        if (lines.size() > 1) {
            throw new ParserException(
                    "Could not parse DATAReply. Expected single line reply but got multiple line reply.");
        }

        if (!startsWithAny(lines.get(0), replyCodes)) {
            throw new ParserException(
                    "Could not parse DATAReply. Not a valid reply code or Malformed reply.");
        }

        String[] line = lines.get(0).split(" ", 2);
        if(line.length > 1) {
            dataReply.setDataMessage(line[1]);
        } else {
            dataReply.setDataMessage(" ");
        }
        dataReply.setReplyCode(Integer.parseInt(line[0]));
    }

    private boolean startsWithAny(String line, List<String> replyCodes) {
        for (String code : replyCodes) {
            if (line.startsWith(code)) {
                return true;
            }
        }
        return false;
    }

}