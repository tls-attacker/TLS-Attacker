/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.DataAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.DataAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.DataAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.DataAttributeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;

public class DataAttribute extends StunAttribute {

    private byte[] dataConfig = null;

    private ModifiableByteArray data;

    public DataAttribute() {
        super(StunAttributeType.DATA);
    }

    public DataAttribute(byte[] dataConfig) {
        super(StunAttributeType.DATA);
        this.dataConfig = dataConfig;
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
    public DataAttributeHandler getHandler(Context context) {
        return new DataAttributeHandler(context);
    }

    @Override
    public DataAttributeParser getParser(Context context, InputStream stream) {
        return new DataAttributeParser(context, stream);
    }

    @Override
    public DataAttributePreparator getPreparator(Context context) {
        return new DataAttributePreparator(context.getChooser(), this);
    }

    @Override
    public DataAttributeSerializer getSerializer(Context context) {
        return new DataAttributeSerializer(this);
    }

    @Override
    public String toShortString() {
        if (data == null || data.getValue() == null) {
            return getType().toString();
        } else {
            byte[] dataValue = data.getValue();
            byte[] tempValue;
            if (dataValue.length > 5) {
                tempValue = Arrays.copyOf(dataValue, 5); // Just copy the first 5 bytes
            } else {
                tempValue = dataValue;
            }
            return getType().toString() + "(" + ArrayConverter.bytesToHexString(tempValue) + ")";
        }
    }
}
