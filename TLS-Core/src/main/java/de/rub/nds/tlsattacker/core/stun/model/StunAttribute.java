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
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.stun.handler.StunAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.StunAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.StunAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.StunAttributeSerializer;
import java.io.InputStream;

public abstract class StunAttribute extends ModifiableVariableHolder
        implements DataContainer<IceContext> {

    private final StunAttributeType type;

    /** 2 bytes */
    private ModifiableByteArray attributeType;

    /** 2 bytes */
    private ModifiableInteger attributeLength;

    /** length many bytes */
    private ModifiableByteArray body;

    private ModifiableByteArray padding;

    public StunAttribute(StunAttributeType type) {
        this.type = type;
    }

    public StunAttributeType getType() {
        return type;
    }

    public ModifiableByteArray getBody() {
        return body;
    }

    public void setBody(ModifiableByteArray body) {
        this.body = body;
    }

    public void setBody(byte[] body) {
        this.body = ModifiableVariableFactory.safelySetValue(this.body, body);
    }

    public ModifiableByteArray getAttributeType() {
        return attributeType;
    }

    public void setAttributeType(ModifiableByteArray attributeType) {
        this.attributeType = attributeType;
    }

    public ModifiableInteger getAttributeLength() {
        return attributeLength;
    }

    public void setAttributeLength(ModifiableInteger attributeLength) {
        this.attributeLength = attributeLength;
    }

    public void setAttributeLength(int attributeLength) {
        this.attributeLength =
                ModifiableVariableFactory.safelySetValue(this.attributeLength, attributeLength);
    }

    public void setAttributeType(byte[] attributeType) {
        this.attributeType =
                ModifiableVariableFactory.safelySetValue(this.attributeType, attributeType);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    @Override
    public abstract StunAttributeHandler<? extends StunAttribute> getHandler(IceContext context);

    @Override
    public abstract StunAttributeParser<? extends StunAttribute> getParser(
            IceContext context, InputStream stream);

    @Override
    public abstract StunAttributePreparator<? extends StunAttribute> getPreparator(
            IceContext context);

    @Override
    public abstract StunAttributeSerializer<? extends StunAttribute> getSerializer(
            IceContext context);
}
