/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELOCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpInitialGreetingDummy;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.ArrayList;
import java.util.List;

public class SmtpContext extends LayerContext {

    private List<String> reversePathBuffer = new ArrayList<>();
    private List<String> forwardPathBuffer = new ArrayList<>();
    private StringBuilder mailDataBuffer = new StringBuilder();
    private String clientIdentity;
    private boolean serverOnlySupportsEHLO = false;

    // SMTP is a back and forth of commands and replies. We need to keep track of each to correctly
    // get the type of the reply
    private SmtpCommand lastCommand = new SmtpInitialGreetingDummy();

    public SmtpContext(Context context) {
        super(context);
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

    public String getClientIdentity() {
        return clientIdentity;
    }

    public void setClientIdentity(String clientIdentity) {
        this.clientIdentity = clientIdentity;
    }

    public SmtpCommand getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(SmtpCommand lastCommand) {
        this.lastCommand = lastCommand;
    }

    public SmtpReply getExpectedNextReplyType() {
        SmtpCommand command = getLastCommand();
        if (command == null) {
            return null;
        } else {
            if (command instanceof SmtpEHLOCommand || command instanceof SmtpHELOCommand) {
                // HELO's reply is a special case of EHLO's reply without any extensions - this just reuses code
                return new SmtpEHLOReply();
            } else if (command instanceof SmtpInitialGreetingDummy) {
                return new SmtpInitialGreeting();
            } else {
                throw new UnsupportedOperationException(
                        "No reply implemented for :" + command.getClass());
            }
        }
    }

    public boolean isServerOnlySupportsEHLO() {
        return serverOnlySupportsEHLO;
    }

    public void setServerOnlySupportsEHLO(boolean serverOnlySupportsEHLO) {
        this.serverOnlySupportsEHLO = serverOnlySupportsEHLO;
    }
}
