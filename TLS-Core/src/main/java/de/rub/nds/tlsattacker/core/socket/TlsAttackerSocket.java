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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.DefaultActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsAttackerSocket {

    private final ActionExecutor executor;
    private final TlsContext context; // TODO Would be better if we could keep
                                      // the context out of this

    public TlsAttackerSocket(TlsContext context) {
        this.context = context;
        this.executor = new DefaultActionExecutor(context);
    }

    /**
     * Sends without encryption etc
     * 
     * @param bytes
     * @throws java.io.IOException
     */
    public void sendRawBytes(byte[] bytes) throws IOException {
        context.getTransportHandler().sendData(bytes);
    }

    /**
     * Listens without Encryption etc
     * 
     * @return
     * @throws java.io.IOException
     */
    public byte[] recieveRawBytes() throws IOException {
        return context.getTransportHandler().fetchData();
    }

    /**
     * Sends a String as ApplicationMessages
     * 
     * @param string
     */
    public void send(String string) {
        send(string.getBytes());
    }

    /**
     * Sends bytes as ApplicationMessages
     * 
     * @param bytes
     *            ApplicationMessages to send
     */
    public void send(byte[] bytes) {
        // If too many bytes we have to split this into multiple application
        // messages TODO
        ApplicationMessage message = new ApplicationMessage();
        message.setDataConfig(bytes);
        send(message);
    }

    /**
     * Recieves bytes and decrypts ApplicationMessage contents
     * 
     * @return Recieved bytes
     * @throws java.io.IOException
     */
    public byte[] receiveBytes() throws IOException {
        MessageActionResult result = executor.receiveMessages(new LinkedList<ProtocolMessage>());
        List<ProtocolMessage> recievedMessages = result.getMessageList();
        List<ApplicationMessage> recievedAppMessages = new LinkedList<>();
        for (ProtocolMessage message : recievedMessages) {
            if (message.getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA) {
                // TODO this could go wrong if a server is not well behaving
                recievedAppMessages.add((ApplicationMessage) message);
            }
        }
        // Collect Data
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (ApplicationMessage message : recievedAppMessages) {
            stream.write(message.getData().getValue());
        }
        return stream.toByteArray();
    }

    /**
     * Recieves bytes and decrypts ApplicationMessage contents in converts them
     * to Strings
     * 
     * @return
     * @throws java.io.IOException
     */
    public String receiveString() throws IOException {
        return new String(receiveBytes());
    }
    
    public void send(ProtocolMessage message)
    {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(message);
        executor.sendMessages(messages, new LinkedList<AbstractRecord>());
    }
    
    public void close()
    {
        AlertMessage closeNotify = new AlertMessage();
        closeNotify.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        send(closeNotify);
        context.getTransportHandler().closeConnection();
    }

}
