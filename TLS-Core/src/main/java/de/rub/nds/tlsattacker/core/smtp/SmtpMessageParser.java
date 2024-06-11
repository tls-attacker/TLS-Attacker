package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.data.Parser;

import java.io.InputStream;

public abstract class SmtpMessageParser<MessageT extends SmtpMessage> extends Parser<MessageT> {
    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data from
     */
    public SmtpMessageParser(InputStream stream) {
        super(stream);
    }
}
