/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import java.util.List;
import org.apache.logging.log4j.Level;

/**
 * Successfully stops workflow execution upon receiving specific HTTP content. TODO: remove in favor
 * of Assertion system
 */
public class ReceiveTillHttpContentConfiguration
        extends ReceiveLayerConfiguration<HttpResponseMessage> {

    private final String desiredContent;

    public ReceiveTillHttpContentConfiguration(
            List<HttpResponseMessage> httpMessages, String desiredContent) {
        super(ImplementedLayers.HTTP, httpMessages);
        this.desiredContent = desiredContent;
    }

    @Override
    public boolean executedAsPlanned(List<HttpResponseMessage> list) {
        StringBuilder stringBuilder = new StringBuilder();
        list.stream().map(e -> e.getResponseContent().getValue()).forEach(stringBuilder::append);
        String content = stringBuilder.toString();
        return content.contains(this.desiredContent);
    }

    @Override
    public String toCompactString() {
        return "(" + getLayerType().getName() + ") ReceiveTillHttpContent: " + desiredContent;
    }

    @Override
    public boolean shouldContinueProcessing(
            List<HttpResponseMessage> list, boolean receivedTimeout, boolean dataLeftToProcess) {
        // Continue processing if we haven't found the desired content yet
        // and there's either more data to process or we haven't reached a timeout
        if (!executedAsPlanned(list)) {
            return !receivedTimeout || dataLeftToProcess;
        }
        // If we found the desired content, stop processing
        return false;
    }

    @Override
    public boolean shouldBeLogged(Level level) {
        return true;
    }
}
