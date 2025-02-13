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
        switch (ehloKeyword) {
            case "8BITMIME":
                return new Smtp8BITMIMEExtension();
            case "ATRN":
                return new SmtpATRNExtension();
            case "AUTH":
                String[] sasl = parameters.split(" ");
                return new SmtpAUTHExtension(new ArrayList<>(List.of(sasl)));
            case "BINARYMIME":
                return new SmtpBINARYMIMEExtension();
            case "BURL":
                // TODO: BURL parameter not understood in any way
                return new SmtpBURLExtension(parameters);
            case "CHECKPOINT":
                return new SmtpCHECKPOINTExtension();
            case "CHUNKING":
                return new SmtpCHUNKINGExtension();
            case "CONNEG":
                return new SmtpCONNEGExtension();
            case "CONPERM":
                return new SmtpCONPERMExtension();
            case "DELIVERBY":
                return new SmtpDELIVERBYExtension();
            case "DSN":
                return new SmtpDSNExtension();
            case "ENHANCEDSTATUSCODES":
                return new SmtpENHANCEDSTATUSCODESExtension();
            case "ETRN":
                return new SmtpETRNExtension();
            case "EXPN":
                return new SmtpEXPNExtension();
            case "FUTURERELEASE":
                return new SmtpFUTURERELEASEExtension();
            case "HELP":
                return new SmtpHELPExtension();
            case "LIMITS":
                return new SmtpLIMITSExtension();
            case "MT-PRIORITY":
                // TODO: MT_PRIORITY parameter not understood in any way
                return new SmtpMT_PRIORITYExtension(parameters);
            case "MTRK":
                return new SmtpMTRKExtension();
            case "NO-SOLICITING":
                // TODO: NO-SOLICITING parameter not understood in any way
                return new SmtpNO_SOLICITINGExtension(parameters);
            case "PIPELINING":
                return new SmtpPIPELININGExtension();
            case "REQUIRETLS":
                return new SmtpREQUIRETLSExtension();
            case "RRVS":
                return new SmtpRRVSExtension();
            case "SAML":
                return new SmtpSAMLExtension();
            case "SEND":
                return new SmtpSENDExtension();
            case "SIZE":
                // TODO: SIZE can have a parameter
                int size = Integer.parseInt(parameters);
                return new SmtpSIZEExtension(size);
            case "SMTPUTF8":
                return new SmtpSMTPUTF8Extension();
            case "SOML":
                return new SmtpSOMLExtension();
            case "STARTTLS":
                return new SmtpSTARTTLSExtension();
            case "SUBMITTER":
                return new SmtpSUBMITTERExtension();
            case "TURN":
                return new SmtpTURNExtension();
            case "VERB":
                return new SmtpVERBExtension();
            default:
                if (keyword.startsWith("X") || keyword.startsWith("x")) {
                    return new SmtpLocalServiceExtension(ehloKeyword, parameters);
                } else {
                    return new SmtpUnknownEHLOExtension(ehloKeyword, parameters);
                    //                    throw new ParserException(
                    //                            "Could not parse EHLOReply. Unknown EHLO keyword:
                    // " + ehloKeyword);
                }
        }
    }
}
