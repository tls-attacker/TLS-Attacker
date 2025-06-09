/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tcp;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TcpStreamContainer implements DataContainer<Context> {

    private transient byte[] configData;

    private ModifiableByteArray data;

    public TcpStreamContainer() {}

    public TcpStreamContainer(byte[] configData) {
        this.configData = configData;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public TcpStreamContainerParser getParser(Context context, InputStream stream) {
        return new TcpStreamContainerParser(stream);
    }

    @Override
    public TcpStreamContainerPreparator getPreparator(Context context) {
        return new TcpStreamContainerPreparator(context.getChooser(), this);
    }

    @Override
    public TcpStreamContainerSerializer getSerializer(Context context) {
        return new TcpStreamContainerSerializer(this);
    }

    @Override
    public TcpStreamContainerHandler getHandler(Context context) {
        return new TcpStreamContainerHandler();
    }

    public byte[] getConfigData() {
        return configData;
    }

    public void setConfigData(byte[] configData) {
        this.configData = configData;
    }

    @Override
    public String toString() {
        return "TCP{" + data.getValue().length + " Bytes}";
    }
}
