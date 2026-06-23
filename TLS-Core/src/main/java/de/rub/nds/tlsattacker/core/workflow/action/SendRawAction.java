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

@XmlRootElement(name = "SendRaw")
public class SendRawAction extends TlsAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] data;

    SendRawAction() {}

    public SendRawAction(byte[] data) {
        this.data = data;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TransportHandler transportHandler = state.getContext().getTransportHandler();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        try {
            LOGGER.info("Sending raw message: {}", DataConverter.bytesToHexString(getData()));
            transportHandler.sendData(getData());
            setExecuted(true);
        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SendRawAction that = (SendRawAction) o;
        return Arrays.equals(data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return this.getClass().getName() + ": " + (isExecuted() ? "(executed)" : "(not executed)");
    }
}
