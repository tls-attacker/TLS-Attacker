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
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAContentReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.ArrayList;
import java.util.List;

public class SmtpContext extends LayerContext {

    // describes the source of the mail (supplied via MAIL FROM)
    private List<String> reversePathBuffer = new ArrayList<>();

    // describes the destination of the mail (supplied via RCPT TO)
    private String forwardPathBuffer = "";

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

    // store the old context to evaluate command injection type vulns with SmtpContext through RESET
    private SmtpContext oldContext;

    // SMTP is a back and forth of commands and replies. We need to keep track of each to correctly
    // get the type of the reply, because the reply type cannot be determined by the content alone.
    private SmtpCommand lastCommand = new SmtpInitialGreetingDummy();

    // The server sends a greeting when the client connects. This is the first message the client
    // has to process, so we need to keep track of it.
    private boolean greetingReceived = false;

    public SmtpContext(Context context) {
        super(context);
    }

    public void clearBuffers() {
        reversePathBuffer.clear();
        forwardPathBuffer = "";
        mailDataBuffer.clear();
    }

    /**
     * Reset the context as intended by the RESET command. The old context is stored to evaluate
     * command injection type vulns with TLSStateVulnFinder.
     */
    public void resetContext() {
        oldContext = new SmtpContext(getContext());
        oldContext.setReversePathBuffer(getReversePathBuffer());
        oldContext.setForwardPathBuffer(getForwardPathBuffer());
        oldContext.setMailDataBuffer(getMailDataBuffer());
    }

    public void insertReversePath(String reversePath) {
        reversePathBuffer.add(reversePath);
    }

    public List<String> getReversePathBuffer() {
        return reversePathBuffer;
    }

    public String getForwardPathBuffer() {
        return forwardPathBuffer;
    }

    public List<String> getMailDataBuffer() {
        return mailDataBuffer;
    }

    public void setReversePathBuffer(List<String> reversePathBuffer) {
        this.reversePathBuffer = reversePathBuffer;
    }

    public void setForwardPathBuffer(String forwardPathBuffer) {
        this.forwardPathBuffer = forwardPathBuffer;
    }

    public void setMailDataBuffer(List<String> mailDataBuffer) {
        this.mailDataBuffer = new ArrayList<>(mailDataBuffer);
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
        return getExpectedReplyType(command);
    }

    /**
     * Given a command return an instance of the Reply object expected fpr ot. Raises an exception
     * when a command is not implemented.
     *
     * @param command The command for which to get the expected reply
     * @return The expected reply object
     */
    public static SmtpReply getExpectedReplyType(SmtpCommand command) {
        if (command == null) {
            return null;
        } else {
            if (command instanceof SmtpEHLOCommand || command instanceof SmtpHELOCommand) {
                // HELO's reply is a special case of EHLO's reply without any extensions - this just
                // reuses code
                return new SmtpEHLOReply();
            } else if (command instanceof SmtpNOOPCommand) {
                return new SmtpNOOPReply();
            } else if (command instanceof SmtpAUTHCommand) {
                return new SmtpAUTHReply();
            } else if (command instanceof SmtpEXPNCommand) {
                return new SmtpEXPNReply();
            } else if (command instanceof SmtpVRFYCommand) {
                return new SmtpVRFYReply();
            } else if (command instanceof SmtpMAILCommand) {
                return new SmtpMAILReply();
            } else if (command instanceof SmtpRSETCommand) {
                return new SmtpRSETReply();
            } else if (command instanceof SmtpInitialGreetingDummy) {
                return new SmtpInitialGreeting();
            } else if (command instanceof SmtpDATACommand) {
                return new SmtpDATAReply();
            } else if (command instanceof SmtpRCPTCommand) {
                return new SmtpRCPTReply();
            } else if (command instanceof SmtpDATAContentCommand) {
                return new SmtpDATAContentReply();
            } else if (command instanceof SmtpHELPCommand) {
                return new SmtpHELPReply();
            } else if (command instanceof SmtpQUITCommand) {
                return new SmtpQUITReply();
            } else if (command instanceof SmtpSTARTTLSCommand) {
                return new SmtpSTARTTLSReply();
            } else {
                throw new UnsupportedOperationException(
                        "No reply implemented for class in SmtpContext:" + command.getClass());
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

    public boolean isGreetingReceived() {
        return greetingReceived;
    }

    public void setGreetingReceived(boolean greetingReceived) {
        this.greetingReceived = greetingReceived;
    }
}
