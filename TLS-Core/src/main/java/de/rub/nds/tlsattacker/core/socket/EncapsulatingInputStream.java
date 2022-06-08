/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

/**
 * An input stream that is reading from a tls attacker state
 *
 */
public class EncapsulatingInputStream extends InputStream {

    private final State state;

    private ByteArrayInputStream inputStream;

    public EncapsulatingInputStream(State state) {
        this.inputStream = new ByteArrayInputStream(new byte[0]);
        this.state = state;
    }

    @Override
    public int read() throws IOException {
        if (available() == 0) {
            checkForNewData();
        }
        return inputStream.read();
    }

    private void checkForNewData() throws IOException {
        ReceiveAction action = new ReceiveAction(new ApplicationMessage());
        action.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
        action.execute(state);
        List<ProtocolMessage> receivedMessages = action.getReceivedMessages();

        List<ApplicationMessage> receivedAppMessages = new LinkedList<>();
        for (ProtocolMessage message : receivedMessages) {
            if (message instanceof ApplicationMessage) {
                receivedAppMessages.add((ApplicationMessage) message);
            }
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ApplicationMessage message : receivedAppMessages) {
            stream.write(message.getData().getValue());
        }
        inputStream = new ByteArrayInputStream(stream.toByteArray());
    }

    @Override
    public int available() throws IOException {
        if (inputStream.available() == 0) {
            checkForNewData();
            return inputStream.available();
        } else {
            return inputStream.available();
        }
    }
}
