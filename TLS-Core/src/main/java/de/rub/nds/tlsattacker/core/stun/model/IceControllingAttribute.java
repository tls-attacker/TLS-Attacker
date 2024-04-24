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
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.IceControllingHandler;
import de.rub.nds.tlsattacker.core.stun.parser.IceControllingParser;
import de.rub.nds.tlsattacker.core.stun.preparator.IceControllingPreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.IceControllingSerializer;
import java.io.InputStream;

public class IceControllingAttribute extends StunAttribute {

    /** 8 byte */
    private ModifiableByteArray tieBreaker;

    public IceControllingAttribute() {
        super(StunAttributeType.ICE_CONTROLLING);
    }

    public ModifiableByteArray getTieBreaker() {
        return tieBreaker;
    }

    public void setTieBreaker(ModifiableByteArray tieBreaker) {
        this.tieBreaker = tieBreaker;
    }

    public void setTieBreaker(byte[] tieBreaker) {
        this.tieBreaker = ModifiableVariableFactory.safelySetValue(this.tieBreaker, tieBreaker);
    }

    @Override
    public IceControllingHandler getHandler(IceContext context) {
        return new IceControllingHandler(context);
    }

    @Override
    public IceControllingParser getParser(IceContext context, InputStream stream) {
        return new IceControllingParser(context, stream);
    }

    @Override
    public IceControllingPreparator getPreparator(IceContext context) {
        return new IceControllingPreparator(context.getChooser(), this);
    }

    @Override
    public IceControllingSerializer getSerializer(IceContext context) {
        return new IceControllingSerializer(this);
    }
}
