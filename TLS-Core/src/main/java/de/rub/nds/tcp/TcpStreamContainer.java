/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tcp;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.io.InputStream;

public class TcpStreamContainer implements DataContainer<LayerContext> {

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
    public TcpStreamContainerParser getParser(LayerContext context, InputStream stream) {
        return new TcpStreamContainerParser(stream);
    }

    @Override
    public TcpStreamContainerPreparator getPreparator(LayerContext context) {
        return new TcpStreamContainerPreparator(context.getChooser(), this);
    }

    @Override
    public TcpStreamContainerSerializer getSerializer(LayerContext context) {
        return new TcpStreamContainerSerializer(this);
    }

    @Override
    public TcpStreamContainerHandler getHandler(LayerContext context) {
        return new TcpStreamContainerHandler();
    }

    public byte[] getConfigData() {
        return configData;
    }

    public void setConfigData(byte[] configData) {
        this.configData = configData;
    }
}
