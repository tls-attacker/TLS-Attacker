package de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The HELP response contains helpful information for the client.
 * It consists of a reply code and human-readable message. If the
 * reply does not follow that syntax, the validSyntax parameter is
 * set to False. HELP replies can be single or multi-line.
 */
@XmlRootElement
public class SmtpHELPReply extends SmtpReply {
}
