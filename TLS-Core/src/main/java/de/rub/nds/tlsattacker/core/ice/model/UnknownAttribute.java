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
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.UnknownAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.UnknownAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.UnknownAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.UnknownAttributeSerializer;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import java.io.InputStream;

public class UnknownAttribute extends StunAttribute {

    private ModifiableByteArray unknownContent;

    /**
     * This takes a type attribute to show known but not implemented attributes Null means its
     * completly unknown
     *
     * @param type
     */
    public UnknownAttribute(StunAttributeType type) {
        super(type);
    }

    public ModifiableByteArray getUnknownContent() {
        return unknownContent;
    }

    public void setUnknownContent(ModifiableByteArray unknownContent) {
        this.unknownContent = unknownContent;
    }

    public void setUnknownContent(byte[] unknownContent) {
        this.unknownContent =
                ModifiableVariableFactory.safelySetValue(this.unknownContent, unknownContent);
    }

    @Override
    public UnknownAttributeHandler getHandler(IceContext context) {
        return new UnknownAttributeHandler(context);
    }

    @Override
    public UnknownAttributeParser getParser(IceContext context, InputStream stream) {
        return new UnknownAttributeParser(context, stream);
    }

    @Override
    public UnknownAttributePreparator getPreparator(IceContext context) {
        return new UnknownAttributePreparator(context.getChooser(), this);
    }

    @Override
    public UnknownAttributeSerializer getSerializer(IceContext context) {
        return new UnknownAttributeSerializer(this);
    }
}
