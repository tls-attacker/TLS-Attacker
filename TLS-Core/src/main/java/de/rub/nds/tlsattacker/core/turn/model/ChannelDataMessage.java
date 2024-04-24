/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.turn.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;

import java.io.InputStream;

public class ChannelDataMessage extends Message<IceContext> {
    private ModifiableInteger channelNumber;

    private ModifiableInteger length;

    private ModifiableByteArray applicationData;

    public ChannelDataMessage() {}

    public ModifiableInteger getChannelNumber() {
        return channelNumber;
    }

    public void setChannelNumber(ModifiableInteger channelNumber) {
        this.channelNumber = channelNumber;
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public ModifiableByteArray getApplicationData() {
        return applicationData;
    }

    public void setApplicationData(ModifiableByteArray applicationData) {
        this.applicationData = applicationData;
    }

    public void setApplicationData(byte[] applicationData) {
        this.applicationData =
                ModifiableVariableFactory.safelySetValue(this.applicationData, applicationData);
    }

    public void setChannelNumber(int channelNumber) {
        this.channelNumber =
                ModifiableVariableFactory.safelySetValue(this.channelNumber, channelNumber);
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    @Override
    public String toShortString() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Handler<?> getHandler(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Parser<?> getParser(IceContext context, InputStream stream) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Preparator<?> getPreparator(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Serializer<?> getSerializer(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }
}
