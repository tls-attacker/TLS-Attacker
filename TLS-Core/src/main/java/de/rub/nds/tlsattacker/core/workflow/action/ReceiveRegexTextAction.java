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
 */
@XmlRootElement(name = "ReceiveRegexText")
public class ReceiveRegexTextAction extends TextAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String regex;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String receivedText;

    private TextReplyTermination termination;

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

    public ReceiveRegexTextAction(String regex, String encoding, TextReplyTermination termination) {
        super(encoding);
        this.regex = regex;
        this.termination = termination;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving text message (expecting /{}/)...", regex);
        TextReplyTermination termination = getTermination();
        Pattern pattern = compilePattern();
        StringBuilder received = new StringBuilder();
        try {
            while (true) {
                byte[] fetchData = tcpContext.getTransportHandler().fetchData();
                if (fetchData == null || fetchData.length == 0) {
                    break;
                }
                received.append(new String(fetchData, getEncoding()));
                if (termination.failsFastOnMismatch()) {
                    Matcher matcher = pattern.matcher(received);
                    if (!matcher.lookingAt() && !matcher.hitEnd()) {
                        receivedText = received.toString();
                        setExecuted(true);
                        throw new WorkflowExecutionException(
                                "Received text \""
                                        + receivedText
                                        + "\" can never match /"
                                        + regex
                                        + "/, aborting STARTTLS upgrade.");
                    }
                }
                if (!isReplyComplete(pattern, received)) {
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

    public TextReplyTermination getTermination() {
        return termination == null ? TextReplyTermination.SINGLE_LINE : termination;
    }

    public void setTermination(TextReplyTermination termination) {
        this.termination = termination;
    }

    public String getReceivedText() {
        return receivedText;
    }

    private Pattern compilePattern() {
        return getTermination().failsFastOnMismatch()
                ? Pattern.compile(regex)
                : Pattern.compile(regex, Pattern.MULTILINE);
    }

    private boolean isReplyComplete(Pattern pattern, CharSequence received) {
        Matcher matcher = pattern.matcher(received);
        boolean matched =
                getTermination().failsFastOnMismatch() ? matcher.lookingAt() : matcher.find();
        return matched && indexOfLineFeed(received, matcher.end()) >= 0;
    }

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
        return isExecuted() && receivedText != null && regex != null && matches(receivedText);
    }

    private boolean matches(CharSequence reply) {
        Matcher matcher = compilePattern().matcher(reply);
        return getTermination().failsFastOnMismatch() ? matcher.lookingAt() : matcher.find();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveRegexTextAction that = (ReceiveRegexTextAction) o;
        return Objects.equals(regex, that.regex)
                && Objects.equals(receivedText, that.receivedText)
                && getTermination() == that.getTermination();
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), regex, receivedText, getTermination());
    }
}
