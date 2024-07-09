/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import java.io.InputStream;
import java.util.List;

public class EXPNReplyParser extends SmtpReplyParser<SmtpEXPNReply> {

    private final String[] validStatusCodes =
            new String[] {"250", "252", "500", "550", "502", "504"};

    public EXPNReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    /**
     * Treats EXPN-reply as a VRFY-553 reply, since they have the same exact format.
     * @param expnReply EXPN-Reply object where data is saved.
     */
    @Override
    public void parse(SmtpEXPNReply expnReply) {
        List<String> lines = parseAllLines();

        SmtpVRFYReply vrfyReply = new SmtpVRFYReply();
        VRFYReplyParser vrfyReplyParser = new VRFYReplyParser(null);
        vrfyReplyParser.setValidStatusCodes(validStatusCodes);
        vrfyReplyParser.parseLines(vrfyReply, lines);

        expnReply.setStatusCode(vrfyReply.getStatusCode());
        expnReply.setDescription(vrfyReply.getDescription());
        if (!vrfyReply.getMailboxes().isEmpty()) expnReply.setMailboxes(vrfyReply.getMailboxes());
        if (!vrfyReply.getFullNames().isEmpty()) expnReply.setFullNames(vrfyReply.getFullNames());
    }
}
