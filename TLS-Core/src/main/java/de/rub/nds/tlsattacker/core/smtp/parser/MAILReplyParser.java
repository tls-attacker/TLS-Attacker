package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpMAILReply;

import java.io.InputStream;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import java.util.Arrays;
import java.util.List;

public class MAILReplyParser extends SmtpReplyParser<SmtpMAILReply> {

    public MAILReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpMAILReply reply) {
        List<String> lines = parseAllLines();
        //save all possible reply codes
        List<String> replyCodes = Arrays.asList("250 ","552 ", "451 ", "452 ", "550 ", "553 ", "503 ", "455 ", "555 ");
        if (lines.size() > 1) {
            throw new ParserException(
                    "Could not parse MAILReply. Expected single line reply but got multiple line reply."
            );
        }
        if (!startsWithAny(lines.get(0),replyCodes)) {
            throw new ParserException(
                    "Could not parse MAILReply. Not a valid reply code or Malformed reply."
            );
        }

        String[] line = lines.get(0).split(" ", 2);
        if (line.length > 1) {
            reply.setMessage(line[1]);
        } else {
            reply.setMessage(" ");
        }
        reply.setReplyCode(Integer.parseInt(line[0]));
    }

    //Check if line Starts with a valid reply code for MAIL command
    private boolean startsWithAny(String line, List<String> replyCodes) {
        for (String code : replyCodes) {
            if (line.startsWith(code)) {
                return true;
            }
        }
        return false;
    }
}
