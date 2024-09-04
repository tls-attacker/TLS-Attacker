/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpEHLOReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EHLOReplyParser extends SmtpReplyParser<SmtpEHLOReply> {

    public EHLOReplyParser(InputStream stream) {
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
                // TODO: create unknown reply of some kind (see: SmtpGenericReplyParser).
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
                return new _8BITMIMEExtension();
            case "ATRN":
                return new ATRNExtension();
            case "AUTH":
                String[] sasl = parameters.split(" ");
                return new AUTHExtension(new ArrayList<>(List.of(sasl)));
            case "BINARYMIME":
                return new BINARYMIMEExtension();
            case "BURL":
                // TODO: BURL parameter not understood in any way
                return new BURLExtension(parameters);
            case "CHECKPOINT":
                return new CHECKPOINTExtension();
            case "CHUNKING":
                return new CHUNKINGExtension();
            case "CONNEG":
                return new CONNEGExtension();
            case "CONPERM":
                return new CONPERMExtension();
            case "DELIVERBY":
                return new DELIVERBYExtension();
            case "DSN":
                return new DSNExtension();
            case "ENHANCEDSTATUSCODES":
                return new ENHANCEDSTATUSCODESExtension();
            case "ETRN":
                return new ETRNExtension();
            case "EXPN":
                return new EXPNExtension();
            case "FUTURERELEASE":
                return new FUTURERELEASEExtension();
            case "HELP":
                return new HELPExtension();
            case "LIMITS":
                return new LIMITSExtension();
            case "MT-PRIORITY":
                // TODO: MT_PRIORITY parameter not understood in any way
                return new MT_PRIORITYExtension(parameters);
            case "MTRK":
                return new MTRKExtension();
            case "NO-SOLICITING":
                // TODO: NO-SOLICITING parameter not understood in any way
                return new NO_SOLICITINGExtension(parameters);
            case "PIPELINING":
                return new PIPELININGExtension();
            case "REQUIRETLS":
                return new REQUIRETLSExtension();
            case "RRVS":
                return new RRVSExtension();
            case "SAML":
                return new SAMLExtension();
            case "SEND":
                return new SENDExtension();
            case "SIZE":
                // TODO: SIZE can have a parameter
                int size = Integer.parseInt(parameters);
                return new SIZEExtension(size);
            case "SMTPUTF8":
                return new SMTPUTF8Extension();
            case "SOML":
                return new SOMLExtension();
            case "STARTTLS":
                return new STARTTLSExtension();
            case "SUBMITTER":
                return new SUBMITTERExtension();
            case "TURN":
                return new TURNExtension();
            case "UTF8SMTP":
                return new UTF8SMTPExtension();
            case "VERB":
                return new VERBExtension();
            default:
                if (keyword.startsWith("X") || keyword.startsWith("x")) {
                    return new LocalSmtpServiceExtension(ehloKeyword, parameters);
                } else {
                    throw new ParserException(
                            "Could not parse EHLOReply. Unknown EHLO keyword: " + ehloKeyword);
                }
        }
    }
}
