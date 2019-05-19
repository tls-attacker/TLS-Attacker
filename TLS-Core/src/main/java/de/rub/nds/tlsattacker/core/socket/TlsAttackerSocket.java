/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.socket;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsAttackerSocket {

    private static final Logger LOGGER = LogManager.getLogger();

    private final State state;

    public TlsAttackerSocket(State state) {
        this.state = state;
    }

    /**
     * Sends without encryption etc
     *
     * @param bytes
     *            The raw bytes which should be send
     * @throws java.io.IOException
     *             If something goes wrong during Transmission
     */
    public void sendRawBytes(byte[] bytes) throws IOException {
        state.getTlsContext().getTransportHandler().sendData(bytes);
    }

    /**
     * Listens without Encryption etc
     *
     * @return The Raw received Bytes
     * @throws java.io.IOException
     *             If something goes wrong during the receive
     */
    public byte[] receiveRawBytes() throws IOException {
        return state.getTlsContext().getTransportHandler().fetchData();
    }

    /**
     * Sends a String as ApplicationMessages
     *
     * @param string
     *            The String which should be send in ApplicationMessages
     */
    public void send(String string) {
        send(string.getBytes(Charset.defaultCharset()));
    }

    /**
     * Sends bytes as ApplicationMessages
     *
     * @param bytes
     *            ApplicationMessages to send
     */
    public void send(byte[] bytes) {
        ApplicationMessage message = new ApplicationMessage();
        ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
        byte[] sendingBytes = new byte[16384];
        int actuallyRead = 0;
        do {
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
    }

    /**
     * Receives bytes and decrypts ApplicationMessage contents
     *
     * @return Received bytes The bytes which are received
     * @throws java.io.IOException
     *             If something goes wrong during the receive
     */
    public byte[] receiveBytes() throws IOException {
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
        return stream.toByteArray();
    }

    /**
     * Receives bytes and decrypts ApplicationMessage contents in converts them
     * to Strings
     *
     * @return The received String
     * @throws java.io.IOException
     *             If something goes wrong during the receive
     */
    public String receiveString() throws IOException {
        return new String(receiveBytes(), Charset.defaultCharset());
    }

    public void send(ProtocolMessage message) {
        SendAction action = new SendAction(message);
        action.setConnectionAlias(state.getTlsContext().getConnection().getAlias());
        action.execute(state);
    }

    public void close() throws IOException {
        AlertMessage closeNotify = new AlertMessage();
        closeNotify.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        send(closeNotify);
        state.getTlsContext().getTransportHandler().closeConnection();
    }

}
