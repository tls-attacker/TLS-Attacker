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
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.reply.*;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.ArrayList;
import java.util.List;

public class SmtpContext extends LayerContext {

    /**
     * Stores the source of the mail (supplied via MAIL FROM) Note <a
     * href="https://datatracker.ietf.org/doc/html/rfc5321#appendix-C">RFC 5321 Appendix C</a>:
     * Historically, the reverse path was a list of hosts, rather than a single host.
     */
    private List<String> reversePathBuffer = new ArrayList<>();

    /** Stores the destination of a mail (supplied via RCPT TO) */
    private String forwardPathBuffer = "";

    /** Stores the recipients of a mail (supplied via MAIL TO). Each entry is a recipient. */
    private List<String> recipientBuffer = new ArrayList<>();

    /** Stores the data of a mail (supplied via DATA). Each entry is a line of the mail. */
    private List<String> mailDataBuffer = new ArrayList<>();

    /**
     * Stores the identity of the client given by EHLO/HELO. See {@link SmtpContext#clientUsedHELO},
     * because legacy HELO clients do not support the client identity being an address literal.
     */
    private String clientIdentity;

    /** Stores the domain of the server given by the EHLO/HELO reply. */
    private String serverIdentity;

    /** Stores the negotiated extensions by the server given by the EHLO reply. */
    private List<SmtpServiceExtension> negotiatedExtensions = new ArrayList<>();

    /**
     * Indicates whether the server supports HELO (which is very old legacy by now). This affects
     * {@link SmtpContext#clientIdentity} and the extension negotiation.
     *
     * @see de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension
     */
    private boolean clientUsedHELO = false;

    /**
     * Whether the client requested to close the connection.
     *
     * <p>Note <a href="https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.1.10">RFC
     * 5321</a>:
     *
     * <blockquote>
     *
     * The sender MUST NOT intentionally close the transmission channel until it sends a QUIT
     * command and it SHOULD wait until it receives the reply (even if there was an error response
     * to a previous command).
     *
     * </blockquote>
     */
    private boolean clientRequestedClose = false;

    /**
     * Whether the server has acknowledged a client's request to close the connection.
     *
     * <p>Note <a href="https://datatracker.ietf.org/doc/html/rfc5321#section-4.1.1.10">RFC
     * 5321</a>:
     *
     * <blockquote>
     *
     * The sender MUST NOT intentionally close the transmission channel until it sends a QUIT
     * command and it SHOULD wait until it receives the reply (even if there was an error response
     * to a previous command).
     *
     * </blockquote>
     */
    private boolean serverAcknowledgedClose = false;

    /**
     * Stores the previous version of an SmtpContext, populated by {@link #resetContext()}. Resets
     * can be directly invoked by the RESET command, but can also be indirectly mandated by the mail
     * transaction flow, see <a
     * href=https://datatracker.ietf.org/doc/html/rfc5321#section-3.3>RFC5321</a>.
     */
    private SmtpContext oldContext;

    /**
     * SMTP is a back and forth of commands and replies. We need to keep track of each to correctly
     * interpret the replies, because the reply type cannot be determined by the content alone.
     *
     * @see de.rub.nds.tlsattacker.core.smtp.SmtpCommandType
     * @see de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer SmtpLayer
     */
    private SmtpCommand lastCommand = new SmtpInitialGreetingDummy();

    /** Whether the initial greeting was received. */
    private boolean greetingReceived = false;

    public SmtpContext(Context context) {
        super(context);
        context.setSmtpContext(this);
    }

    /** Clear all buffers. */
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

    /**
     * Get the expected reply type for the last command.
     *
     * @return An object of the expected reply type for the last command.
     */
    public SmtpReply getExpectedNextReplyType() {
        SmtpCommand command = getLastCommand();
        return command.getCommandType().createReply();
    }

    public boolean isClientUsedHELO() {
        return clientUsedHELO;
    }

    public void setClientUsedHELO(boolean clientUsedHELO) {
        this.clientUsedHELO = clientUsedHELO;
    }

    public boolean isClientRequestedClose() {
        return clientRequestedClose;
    }

    public void setClientRequestedClose(boolean clientRequestedClose) {
        this.clientRequestedClose = clientRequestedClose;
    }

    public boolean getServerAcknowledgedClose() {
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

    public SmtpContext getOldContext() {
        return oldContext;
    }

    public String getServerIdentity() {
        return serverIdentity;
    }

    public void setServerIdentity(String serverIdentity) {
        this.serverIdentity = serverIdentity;
    }

    public List<SmtpServiceExtension> getNegotiatedExtensions() {
        return negotiatedExtensions;
    }

    public void setNegotiatedExtensions(List<SmtpServiceExtension> negotiatedExtensions) {
        this.negotiatedExtensions = negotiatedExtensions;
    }
}
