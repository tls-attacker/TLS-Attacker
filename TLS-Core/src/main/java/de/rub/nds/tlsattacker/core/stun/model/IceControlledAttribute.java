/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.model;

import java.io.InputStream;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.IceControlledHandler;
import de.rub.nds.tlsattacker.core.stun.parser.IceControlledParser;
import de.rub.nds.tlsattacker.core.stun.preparator.IceControlledPreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.IceControlledSerializer;

public class IceControlledAttribute extends StunAttribute {

    /** 8 byte */
    private ModifiableByteArray tieBreaker;

    public IceControlledAttribute() {
        super();
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
