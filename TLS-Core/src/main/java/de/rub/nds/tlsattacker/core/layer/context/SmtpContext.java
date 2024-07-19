/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.smtp.command.*;
import de.rub.nds.tlsattacker.core.smtp.reply.*;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.ArrayList;
import java.util.List;

public class SmtpContext extends LayerContext {

    private List<String> reversePathBuffer = new ArrayList<>();
    private List<String> forwardPathBuffer = new ArrayList<>();
    private List<String> recipientBuffer = new ArrayList<>();
    private List<String> mailDataBuffer = new ArrayList<>();
    private String clientIdentity;
    private boolean serverOnlySupportsEHLO = false;

    // Client can request connection close via QUIT, but MUST NOT close the connection itself
    // intentionally before that
    private boolean clientRequestedClose = false;
    // Clients SHOULD NOT close the connection until they have received the reply indicating the
    // server has
    private boolean serverAcknowledgedClose = false;

    // SMTP is a back and forth of commands and replies. We need to keep track of each to correctly
    // get the type of the reply
    private SmtpCommand lastCommand = new SmtpInitialGreetingDummy();

    public SmtpContext(Context context) {
        super(context);
    }

    public void clearBuffers() {
        reversePathBuffer.clear();
        forwardPathBuffer.clear();
        mailDataBuffer.clear();
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

    public List<String> getMailDataBuffer() {
        return mailDataBuffer;
    }

    public void setReversePathBuffer(List<String> reversePathBuffer) {
        this.reversePathBuffer = reversePathBuffer;
    }

    public void setForwardPathBuffer(List<String> forwardPathBuffer) {
        this.forwardPathBuffer = forwardPathBuffer;
    }

    public void setMailDataBuffer(List<String> mailDataBuffer) {
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
                // HELO's reply is a special case of EHLO's reply without any extensions - this just
                // reuses code
                return new SmtpEHLOReply();
            } else if (command instanceof SmtpNOOPCommand) {
                return new SmtpNOOPReply();
            } else if (command instanceof SmtpInitialGreetingDummy) {
                return new SmtpInitialGreeting();
            } else if (command instanceof SmtpDATACommand) {
                return new SmtpDATAReply();
            } else if (command instanceof SmtpDATAContentCommand) {
                return new SmtpDATAContentReply();
            } else if (command instanceof SmtpQUITCommand) {
                return new SmtpQUITReply();
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

    public boolean isClientRequestedClose() {
        return clientRequestedClose;
    }

    public void setClientRequestedClose(boolean clientRequestedClose) {
        this.clientRequestedClose = clientRequestedClose;
    }

    public boolean isServerAcknowledgedClose() {
        return serverAcknowledgedClose;
    }

    public void setServerAcknowledgedClose(boolean serverAcknowledgedClose) {
        this.serverAcknowledgedClose = serverAcknowledgedClose;
    }

    public List<String> getRecipientBuffer() {
        return recipientBuffer;
    }

    public void setRecipientBuffer(List<String> recipientBuffer) {
        this.recipientBuffer = recipientBuffer;
    }
}
