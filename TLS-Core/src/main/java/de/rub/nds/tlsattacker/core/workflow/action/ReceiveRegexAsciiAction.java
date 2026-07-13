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
 * Receives a plaintext ASCII message and validates it against a regular expression. Unlike {@link
 * GenericReceiveAsciiAction}, which succeeds as soon as any bytes are read, this action only counts
 * as executed-as-planned when the received text matches the configured pattern. This lets STARTTLS
 * control-channel exchanges assert on the protocol status code (e.g. FTP "234" for an accepted
 * "AUTH TLS") and fail the workflow when the server refuses the upgrade instead of silently
 * proceeding.
 */
@XmlRootElement(name = "ReceiveRegexAscii")
public class ReceiveRegexAsciiAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String regex;

    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String receivedAsciiString;

    @SuppressWarnings("unused")
    ReceiveRegexAsciiAction() {
        super();
    }

    public ReceiveRegexAsciiAction(String regex) {
        super((String) null);
        this.regex = regex;
    }

    public ReceiveRegexAsciiAction(String regex, String encoding) {
        super(encoding);
        this.regex = regex;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TcpContext tcpContext = state.getTcpContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving ASCII message (expecting /{}/)...", regex);
        Pattern pattern = Pattern.compile(regex);
        StringBuilder received = new StringBuilder();
        try {
            while (true) {
                byte[] fetchData = tcpContext.getTransportHandler().fetchData();
                if (fetchData == null || fetchData.length == 0) {
                    break;
                }
                received.append(new String(fetchData, getEncoding()));
                Matcher matcher = pattern.matcher(received);
                if (!matcher.lookingAt() && !matcher.hitEnd()) {
                    receivedAsciiString = received.toString();
                    setExecuted(true);
                    throw new WorkflowExecutionException(
                            "Received text \""
                                    + receivedAsciiString
                                    + "\" can never match /"
                                    + regex
                                    + "/, aborting STARTTLS upgrade.");
                }
                if (received.indexOf("\n") < 0) {
                    LOGGER.debug(
                            "Reply not yet a full line (/{}/), waiting for more data...", received);
                    continue;
                }
                break;
            }
            receivedAsciiString = received.toString();
            LOGGER.info("Received: {}", receivedAsciiString);
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            if (!received.isEmpty()) {
                receivedAsciiString = received.toString();
            }
            setExecuted(false);
        }
    }

    public String getRegex() {
        return regex;
    }

    public String getReceivedAsciiString() {
        return receivedAsciiString;
    }

    @Override
    public void reset() {
        receivedAsciiString = null;
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted()
                && receivedAsciiString != null
                && regex != null
                && Pattern.compile(regex).matcher(receivedAsciiString).lookingAt();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveRegexAsciiAction that = (ReceiveRegexAsciiAction) o;
        return Objects.equals(regex, that.regex)
                && Objects.equals(receivedAsciiString, that.receivedAsciiString);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), regex, receivedAsciiString);
    }
}
