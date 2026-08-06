/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TcpContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Receives a plaintext message and validates it against a regular expression. Unlike {@link
 * GenericReceiveTextAction}, which succeeds as soon as any bytes are read, this action only counts
 * as executed-as-planned when the received text matches the configured pattern. This lets STARTTLS
 * control-channel exchanges assert on the protocol status code (e.g. FTP "234" for an accepted
 * "AUTH TLS") and fail the workflow when the server refuses the upgrade instead of silently
 * proceeding.
 *
 * <p>The reply is read until the pattern matches on a terminated line, so a reply spanning several
 * lines and arriving in several TCP packets is drained in full. The regex is what says where the
 * reply ends - {@code ^234 } for FTP's final status line, {@code ^a001 OK} for IMAP's tagged one -
 * which is how one rule covers protocols that delimit their replies differently.
 */
@XmlRootElement(name = "ReceiveRegexText")
public class ReceiveRegexTextAction extends TextAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String regex;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String abortRegex;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String receivedText;

    @SuppressWarnings("unused")
    ReceiveRegexTextAction() {
        super();
    }

    public ReceiveRegexTextAction(String regex) {
        super((String) null);
        this.regex = regex;
    }

    public ReceiveRegexTextAction(String regex, String encoding) {
        super(encoding);
        this.regex = regex;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving text message (expecting /{}/)...", regex);
        Pattern pattern = compile(regex);
        Pattern abortPattern = abortRegex == null ? null : compile(abortRegex);
        StringBuilder received = new StringBuilder();
        try {
            while (true) {
                byte[] fetchData = tcpContext.getTransportHandler().fetchData();
                if (fetchData == null || fetchData.length == 0) {
                    break;
                }
                received.append(new String(fetchData, getEncoding()));
                if (abortPattern != null && isCompleteMatch(abortPattern, received)) {
                    receivedText = received.toString();
                    setExecuted(true);
                    throw new WorkflowExecutionException(
                            "Received text \""
                                    + receivedText.trim()
                                    + "\" matches the refusal pattern /"
                                    + abortRegex
                                    + "/, aborting STARTTLS upgrade.");
                }
                if (!isCompleteMatch(pattern, received)) {
                    LOGGER.debug(
                            "Reply not yet complete (/{}/), waiting for more data...", received);
                    continue;
                }
                break;
            }
            receivedText = received.toString();
            LOGGER.info("Received: {}", receivedText);
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            if (!received.isEmpty()) {
                receivedText = received.toString();
            }
            setExecuted(false);
        }
    }

    public String getRegex() {
        return regex;
    }

    public String getAbortRegex() {
        return abortRegex;
    }

    public void setAbortRegex(String abortRegex) {
        this.abortRegex = abortRegex;
    }

    public String getReceivedText() {
        return receivedText;
    }

    /**
     * Compiles with {@link Pattern#MULTILINE} so that an anchored pattern such as {@code ^234 }
     * binds to the start of any line rather than only to the start of the whole reply.
     */
    private static Pattern compile(String regex) {
        return Pattern.compile(regex, Pattern.MULTILINE);
    }

    /**
     * Whether the pattern has matched on a line that has since been terminated.
     *
     * <p>Requiring the terminator is what keeps this one rule working across protocols that delimit
     * replies differently - FTP's space-after-code final line, IMAP's tagged line after its
     * untagged ones, NNTP's lone dot - because in each case the pattern describes the line that
     * ends the reply. It also stops the read from ending mid-line when the pattern matches on a
     * prefix: leaving the rest of the line in the socket would push plaintext into the TLS
     * handshake that follows.
     */
    private static boolean isCompleteMatch(Pattern pattern, CharSequence received) {
        Matcher matcher = pattern.matcher(received);
        return matcher.find() && indexOfLineFeed(received, matcher.end()) >= 0;
    }

    /** Index of the next LF at or after {@code fromIndex}, or -1 if there is none. */
    private static int indexOfLineFeed(CharSequence received, int fromIndex) {
        for (int i = fromIndex; i < received.length(); i++) {
            if (received.charAt(i) == '\n') {
                return i;
            }
        }
        return -1;
    }

    @Override
    public void reset() {
        receivedText = null;
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted()
                && receivedText != null
                && regex != null
                && compile(regex).matcher(receivedText).find();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveRegexTextAction that = (ReceiveRegexTextAction) o;
        return Objects.equals(regex, that.regex)
                && Objects.equals(abortRegex, that.abortRegex)
                && Objects.equals(receivedText, that.receivedText);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), regex, abortRegex, receivedText);
    }
}
