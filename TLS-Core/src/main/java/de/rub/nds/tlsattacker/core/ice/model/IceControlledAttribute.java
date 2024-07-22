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
import de.rub.nds.tlsattacker.core.ice.handler.IceControlledHandler;
import de.rub.nds.tlsattacker.core.ice.parser.IceControlledParser;
import de.rub.nds.tlsattacker.core.ice.preparator.IceControlledPreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.IceControlledSerializer;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import java.io.InputStream;

public class IceControlledAttribute extends StunAttribute {

    /** 8 byte */
    private ModifiableByteArray tieBreaker;

    public IceControlledAttribute() {
        super(StunAttributeType.ICE_CONTROLLED);
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
    public IceControlledHandler getHandler(IceContext context) {
        return new IceControlledHandler(context);
    }

    @Override
    public IceControlledParser getParser(IceContext context, InputStream stream) {
        return new IceControlledParser(context, stream);
    }

    @Override
    public IceControlledPreparator getPreparator(IceContext context) {
        return new IceControlledPreparator(context.getChooser(), this);
    }

    @Override
    public IceControlledSerializer getSerializer(IceContext context) {
        return new IceControlledSerializer(this);
    }
}
