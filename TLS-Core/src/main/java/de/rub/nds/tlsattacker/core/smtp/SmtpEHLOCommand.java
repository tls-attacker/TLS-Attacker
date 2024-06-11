package de.rub.nds.tlsattacker.core.smtp;

import org.bouncycastle.util.IPAddress;

/**
 * This class represents an SMTP EHLO command, which is used to identify the client to the server.
 * The EHLO command mostly replaces the old HELO command: The difference is that EHLO can be used with an address literal
 * as well as a domain, rather than just a domain.
 *
 */
public class SmtpEHLOCommand extends SmtpCommand {
    public SmtpEHLOCommand(String domain) {
        super("EHLO", domain);
    }
    public SmtpEHLOCommand(IPAddress ip) {
        super("EHLO", ip.toString());
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }
}
