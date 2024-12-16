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
import de.rub.nds.tlsattacker.core.ice.handler.IceControllingHandler;
import de.rub.nds.tlsattacker.core.ice.parser.IceControllingParser;
import de.rub.nds.tlsattacker.core.ice.preparator.IceControllingPreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.IceControllingSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
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
    public IceControllingHandler getHandler(Context context) {
        return new IceControllingHandler(context.getIceContext());
    }

    @Override
    public IceControllingParser getParser(Context context, InputStream stream) {
        return new IceControllingParser(context.getIceContext(), stream);
    }

    @Override
    public IceControllingPreparator getPreparator(Context context) {
        return new IceControllingPreparator(context.getChooser(), this);
    }

    @Override
    public IceControllingSerializer getSerializer(Context context) {
        return new IceControllingSerializer(this);
    }
}
