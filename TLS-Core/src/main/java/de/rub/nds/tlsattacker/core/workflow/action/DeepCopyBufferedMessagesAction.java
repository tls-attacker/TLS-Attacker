/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.LinkedList;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class DeepCopyBufferedMessagesAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public DeepCopyBufferedMessagesAction() {
    }

    public DeepCopyBufferedMessagesAction(String srcConnectionAlias, String dstConnectionAlias) {
        super(srcConnectionAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        deepCopyMessages(src, dst);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    private void deepCopyMessages(TlsContext src, TlsContext dst) {
        LinkedList<ProtocolMessage> messageBuffer = new LinkedList<>();
        ObjectOutputStream outStream;
        ObjectInputStream inStream;
        try {
            for (ProtocolMessage message : src.getMessageBuffer()) {

                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                outStream = new ObjectOutputStream(stream);
                outStream.writeObject(message);
                outStream.close();
                inStream = new ObjectInputStream(new ByteArrayInputStream(stream.toByteArray()));
                ProtocolMessage messageCopy = (ProtocolMessage) inStream.readObject();

                messageBuffer.add(messageCopy);
                setExecuted(true);
            }
        } catch (IOException | ClassNotFoundException ex) {
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
            LOGGER.error("Error while creating deep copy of messageBuffer");
            throw new WorkflowExecutionException(ex.toString());
        }

        dst.setMessageBuffer(messageBuffer);
    }
}
