package de.rub.nds.tlsattacker.core.smtp.command;

import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpDATACommand extends SmtpCommand {
    private static final String COMMAND = "DATA";

    public SmtpDATACommand() { super(COMMAND, null);}
}
