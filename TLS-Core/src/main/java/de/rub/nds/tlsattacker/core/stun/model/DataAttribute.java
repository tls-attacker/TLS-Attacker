/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.DataAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.DataAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.DataAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.DataAttributeSerializer;
import java.io.InputStream;

public class DataAttribute extends StunAttribute {

    private byte[] dataConfig = null;

    private ModifiableByteArray data;

    public DataAttribute() {
        super();
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
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
    public DataAttributeHandler getHandler(IceContext context) {
        return new DataAttributeHandler(context);
    }

    @Override
    public DataAttributeParser getParser(IceContext context, InputStream stream) {
        return new DataAttributeParser(context, stream);
    }

    @Override
    public DataAttributePreparator getPreparator(IceContext context) {
        return new DataAttributePreparator(context.getChooser(), this);
    }

    @Override
    public DataAttributeSerializer getSerializer(IceContext context) {
        return new DataAttributeSerializer(this);
    }
}
