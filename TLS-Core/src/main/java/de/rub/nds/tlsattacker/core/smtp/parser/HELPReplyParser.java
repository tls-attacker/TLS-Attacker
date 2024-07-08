package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpHELPReply;

import java.io.InputStream;
import java.util.List;

public class HELPReplyParser extends SmtpReplyParser<SmtpHELPReply> {
    public HELPReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpHELPReply smtpHELPReply) {
        List<String> lines = parseAllLines();

        String firstLine = lines.get(0);
        // help type reply has code 214 and is followed by the requested information
        if((firstLine.startsWith("211 ")) || (firstLine.startsWith("214 "))) {
            throw new ParserException("Could not parse HELPReply. Expected '250 ' for final line but got: " + lines.get(lines.size() - 1));
        }

        String domainAndGreeting = lines.get(0);
        //in both cases the first is almost the same
        String[] parts = domainAndGreeting.substring(4).split(" ", 2);
        if(parts.length == 1) {
            smtpHELPReply.setDomain(parts[0]);
        } else if(parts.length == 2) {
            smtpHELPReply.setDomain(parts[0]);
            smtpHELPReply.setGreeting(parts[1]);
        } else {
            throw new ParserException("Could not parse HELPReply. Malformed 250: " + domainAndGreeting);
        }
    }
}
