/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.IOException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ReceiveRaw")
public class ReceiveRawAction extends MessageAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] expectedData;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] receivedData;

    private ReceiveRawAction() {}

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }

    public ReceiveRawAction(byte[] expectedData) {
        this.expectedData = expectedData;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TransportHandler transportHandler = state.getContext().getTransportHandler();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        try {
            LOGGER.debug("Receiving raw message...");
            receivedData = transportHandler.fetchData();
            LOGGER.info("Received: {}", DataConverter.bytesToHexString(receivedData));

            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    public byte[] getExpectedData() {
        return expectedData;
    }

    public void setExpectedData(byte[] expectedData) {
        this.expectedData = expectedData;
    }

    public byte[] getReceivedData() {
        return receivedData;
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return Arrays.equals(receivedData, expectedData);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ReceiveRawAction that = (ReceiveRawAction) o;
        return Arrays.equals(expectedData, that.expectedData)
                && Arrays.equals(receivedData, that.receivedData);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(expectedData);
        result = 31 * result + Arrays.hashCode(receivedData);
        return result;
    }
}
