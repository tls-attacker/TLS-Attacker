/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.*;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SmtpCommand extends SmtpMessage {

    private List<String> reversePathBuffer;
    private List<String> forwardPathBuffer;
    private StringBuilder mailDataBuffer;

    String verb;
    String parameters;

    public SmtpCommand(String verb, String parameters) {
        super();
        this.verb = verb;
        this.parameters = parameters;
    }

    public SmtpCommand() {}

    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        return null;
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpCommandParser<>(stream);
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

    public void clearBuffers() {
        reversePathBuffer.clear();
        forwardPathBuffer.clear();
        mailDataBuffer.setLength(0);
    }

    public void insertReversePath(String reversePath) {
        reversePathBuffer.add(reversePath);
    }

    public List<String> getReversePathBuffer() {
        return reversePathBuffer;
    }

    public List<String> getForwardPathBuffer() {
        return forwardPathBuffer;
    }

    public StringBuilder getMailDataBuffer() {
        return mailDataBuffer;
    }

    public void setReversePathBuffer(List<String> reversePathBuffer) {
        this.reversePathBuffer = reversePathBuffer;
    }

    public void setForwardPathBuffer(List<String> forwardPathBuffer) {
        this.forwardPathBuffer = forwardPathBuffer;
    }

    public void setMailDataBuffer(StringBuilder mailDataBuffer) {
        this.mailDataBuffer = mailDataBuffer;
    }

}
