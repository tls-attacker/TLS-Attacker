/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** An input stream that is reading from a tls attacker state */
public class EncapsulatingOutputStream extends OutputStream {

    private Logger LOGGER = LogManager.getLogger();

    private final State state;

    private ByteArrayOutputStream outputStream;

    public EncapsulatingOutputStream(State state) {
        this.outputStream = new ByteArrayOutputStream();
        this.state = state;
    }

    @Override
    public void write(int i) throws IOException {
        outputStream.write(i);
    }

    @Override
    public void flush() throws IOException {
        ApplicationMessage message = new ApplicationMessage();
        ByteArrayInputStream stream = new ByteArrayInputStream(outputStream.toByteArray());
        byte[] sendingBytes = new byte[16384];
        int actuallyRead;
        do {
            actuallyRead = 0;
            try {
                actuallyRead = stream.read(sendingBytes);
                if (actuallyRead > 0) {
                    message.setDataConfig(Arrays.copyOf(sendingBytes, actuallyRead));
                    send(message);
                }
            } catch (IOException ex) {
                LOGGER.warn(ex);
            }
        } while (actuallyRead > 0);
        outputStream = new ByteArrayOutputStream();
    }

    private void send(ProtocolMessage message) {
        SendAction action = new SendAction(message);
        action.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
        action.execute(state);
    }
}
