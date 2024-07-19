/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import java.io.InputStream;
import java.util.List;

public class EXPNReplyParser extends SmtpReplyParser<SmtpEXPNReply> {

    public EXPNReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(SmtpEXPNReply expnReply) {
        List<String> lines = readWholeReply();

        SmtpVRFYReply vrfyReply = new SmtpVRFYReply();
        VRFYReplyParser vrfyReplyParser = new VRFYReplyParser(null);
        vrfyReplyParser.parseLines(vrfyReply, lines);

        expnReply.setReplyCode(vrfyReply.getReplyCode());
        if (!vrfyReply.getMailboxes().isEmpty()) expnReply.setMailboxes(vrfyReply.getMailboxes());
        expnReply.setReplyLines(vrfyReply.getReplyLines());
    }
}
