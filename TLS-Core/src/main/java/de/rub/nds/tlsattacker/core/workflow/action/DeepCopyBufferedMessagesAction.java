/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.*;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class DeepCopyBufferedMessagesAction extends CopyContextFieldAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public DeepCopyBufferedMessagesAction() {}

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
        ObjectInputStream inStream;
        ObjectOutputStream outStream;
        try {
            for (ProtocolMessage message : src.getMessageBuffer()) {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                outStream = new ObjectOutputStream(stream);
                outStream.writeObject(message);
                inStream = new ObjectInputStream(new ByteArrayInputStream(stream.toByteArray()));
                ProtocolMessage messageCopy = (ProtocolMessage) inStream.readObject();

                messageBuffer.add(messageCopy);
                setExecuted(true);
            }
        } catch (IOException | ClassNotFoundException ex) {
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
            LOGGER.error("Error while creating deep copy of messageBuffer");
            throw new ActionExecutionException(ex.toString());
        }
        dst.setMessageBuffer(messageBuffer);
    }
}
