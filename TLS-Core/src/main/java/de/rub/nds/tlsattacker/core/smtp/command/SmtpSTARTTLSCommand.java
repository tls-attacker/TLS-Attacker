package de.rub.nds.tlsattacker.core.smtp.command;

import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpSTARTTLSCommand extends SmtpCommand {
    public SmtpSTARTTLSCommand(String verb, String parameters) {
        super(verb, parameters);
    }

    public SmtpSTARTTLSCommand() {
        super("STARTTLS");
    }
}
