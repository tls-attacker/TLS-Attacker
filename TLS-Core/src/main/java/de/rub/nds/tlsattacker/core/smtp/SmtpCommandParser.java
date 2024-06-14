package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;

import java.io.InputStream;

public class SmtpCommandParser extends SmtpMessageParser<SmtpCommand> {

    private static final byte SP = 0x20 ;
    private static final byte CR = 0x0D;
    private static final byte LF = 0x0A;

    public SmtpCommandParser(InputStream stream) {
        super(stream);
    }

    public void parse(SmtpCommand smtpCommand) {
        // parseStringTill(CRLF) is sadly not possible
        String untilCR = parseStringTill(CR);
        if (getBytesLeft() != 2) {
            throw new ParserException("Could not parse as SmtpCommand: Command does not end with CRLF");
        }
        byte lf = parseByteField(1);
        if (lf != LF) {
            throw new ParserException("Could not parse as SmtpCommand: Command does not end with CRLF");
        }
        String[] split = untilCR.trim().split(" ", 2);

        smtpCommand.setVerb(split[0]);
        if (split.length > 1) {
            smtpCommand.setParameters(split[1]);
        }
    }
}
