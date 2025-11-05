/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SmtpEHLOReplyParser extends SmtpReplyParser<SmtpEHLOReply> {

    public SmtpEHLOReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpEHLOReply smtpEHLOReply) {
        List<String> lines = readWholeReply();

        this.parseReplyCode(smtpEHLOReply, lines.get(0));

        if (lines.get(0).length() > 4) {
            String domainAndGreeting = lines.get(0);
            // in both cases the first is almost the same
            String[] parts = domainAndGreeting.substring(4).split(" ", 2);
            if (parts.length == 1) {
                smtpEHLOReply.setDomain(parts[0]);
            } else if (parts.length == 2) {
                smtpEHLOReply.setDomain(parts[0]);
                smtpEHLOReply.setGreeting(parts[1]);
            } else {
                // TODO: catch in appropriate spot in layer system
            }
        }

        for (String line : lines.subList(1, lines.size())) {
            this.checkReplyCodeConsistency(smtpEHLOReply.getReplyCode(), line.substring(0, 3));

            String keyword = line.substring(4);
            SmtpServiceExtension extension = parseKeyword(keyword);
            smtpEHLOReply.getExtensions().add(extension);
        }
    }

    public SmtpServiceExtension parseKeyword(String keyword) {
        // just ehlo-line
        String[] parts = keyword.split(" ", 2);
        String ehloKeyword = parts[0];
        String parameters;
        if (parts.length > 1) {
            parameters = parts[1];
        } else {
            parameters = "";
        }
        return new SmtpServiceExtension(ehloKeyword, parameters);
    }
}
