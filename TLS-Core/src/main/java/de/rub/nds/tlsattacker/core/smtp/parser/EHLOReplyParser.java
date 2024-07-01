package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.util.List;

public class EHLOReplyParser extends SmtpReplyParser<SmtpEHLOReply> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EHLOReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpEHLOReply smtpEHLOReply) {
        LOGGER.trace("Parsing EHLOReply");
        List<String> lines = parseAllLines();
        LOGGER.trace("Parsing lines: {}", lines);

        //only the last line can be '250 ' the others must be '250-', check for both
        if(!lines.get(lines.size() - 1).startsWith("250 ")) {
            LOGGER.trace("Could not parse EHLOReply. Expected '250 ' for final line but got: {}", lines.get(lines.size() - 1));
            throw new ParserException("Could not parse EHLOReply. Expected '250 ' for final line but got: " + lines.get(lines.size() - 1));
        }
        for(int i = 1; i < lines.size() - 1; i++) {
            if(!lines.get(i).startsWith("250-")) {
                LOGGER.trace("Could not parse EHLOReply. Expected '250-' for multiline but got: {}", lines.get(i));
                throw new ParserException("Could not parse EHLOReply. Expected '250-' for multiline but got: " + lines.get(i));
            }
        }

        String domainAndGreeting = lines.get(0);
        //in both cases the first is almost the same
        String[] parts = domainAndGreeting.substring(4).split(" ", 2);
        if(parts.length == 1) {
            smtpEHLOReply.setDomain(parts[0]);
        } else if(parts.length == 2) {
            smtpEHLOReply.setDomain(parts[0]);
            smtpEHLOReply.setGreeting(parts[1]);
        } else {
            throw new ParserException("Could not parse EHLOReply. Malformed 250: " + domainAndGreeting);
        }

        if(lines.size() > 1) {
            for(int i = 1; i < lines.size(); i++) {
                SmtpServiceExtension extension = parseKeyword(lines.get(i).substring(4));
                smtpEHLOReply.getExtensions().add(extension);
            }
        }
        smtpEHLOReply.setReplyCode(250);
    }
    public SmtpServiceExtension parseKeyword(String keyword) {
        //just ehlo-line
        String[] parts = keyword.split(" ", 2);
        String ehloKeyword = parts[0];
        String parameters;
        if(parts.length > 1) {
            parameters = parts[1];
        } else {
            parameters = "";
        }
        switch(ehloKeyword) {
            case "8BITMIME":
                return new _8BITMIMEExtension();
            case "ATRN":
                return new ATRNExtension();
            case "AUTH":
                // TODO: AUTH can have a parameter
                return new AUTHExtension();
            case "BINARYMIME":
                return new BINARYMIMEExtension();
            case "BURL":
                //TODO: BURL can have a parameter
                return new BURLExtension();
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
                //TODO: MT-PRIORITY can have a parameter
                return new MT_PRIORITYExtension();
            case "MTRK":
                return new MTRKExtension();
            case "NO-SOLICITING":
                //TODO: NO-SOLICITING can have a parameter
                return new NO_SOLICITINGExtension();
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
                //TODO: SIZE can have a parameter
                return new SIZEExtension();
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
                if(keyword.startsWith("X") || keyword.startsWith("x")) {
                    return new LocalSmtpServiceExtension(ehloKeyword, parameters);
                } else {
                    throw new ParserException("Could not parse EHLOReply. Unknown EHLO keyword: " + ehloKeyword);
                }
        }
    }

}
