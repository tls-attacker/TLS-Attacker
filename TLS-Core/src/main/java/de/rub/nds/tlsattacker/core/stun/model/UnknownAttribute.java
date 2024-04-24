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
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.UnknownAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.UnknownAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.UnknownAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.UnknownAttributeSerializer;
import java.io.InputStream;

public class UnknownAttribute extends StunAttribute {

    private ModifiableByteArray unknownContent;

    public UnknownAttribute() {
        super();
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
