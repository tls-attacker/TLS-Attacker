package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;

import java.io.InputStream;

public class SmtpCommand extends SmtpMessage {

    String verb;
    String parameters;

    public SmtpCommand(String verb, String parameters) {
        super();
        this.verb = verb;
        this.parameters = parameters;
    }

    public SmtpCommand() {

    }


    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        return null;
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(SmtpContext context, InputStream stream) {
        return new SmtpCommandParser(stream);
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return null;
    }

    @Override
    public SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context) {
        return new SmtpCommandSerializer(this);
    }

    @Override
    public String toShortString() {
        return "SMTP_CMD";
    }

    public String getVerb() {
        return verb;
    }

    public void setVerb(String verb) {
        this.verb = verb;
    }

    public String getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = parameters;
    }
}
