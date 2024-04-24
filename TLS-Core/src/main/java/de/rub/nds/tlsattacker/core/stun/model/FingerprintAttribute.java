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
import de.rub.nds.tlsattacker.core.stun.handler.FingerprintAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.FingerprintAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.FingerprintAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.FingerprintAttributeSerializer;
import java.io.InputStream;

public class FingerprintAttribute extends StunAttribute {

    /** 8 byte */
    private ModifiableByteArray crcChecksum;

    public FingerprintAttribute() {
        super();
    }

    public ModifiableByteArray getCrcChecksum() {
        return crcChecksum;
    }

    public void setCrcChecksum(ModifiableByteArray crcChecksum) {
        this.crcChecksum = crcChecksum;
    }

    public void setCrcChecksum(byte[] crcChecksum) {
        this.crcChecksum = ModifiableVariableFactory.safelySetValue(this.crcChecksum, crcChecksum);
    }

    @Override
    public FingerprintAttributeHandler getHandler(IceContext context) {
        return new FingerprintAttributeHandler(context);
    }

    @Override
    public FingerprintAttributeParser getParser(IceContext context, InputStream stream) {
        return new FingerprintAttributeParser(context.getIceChooser().getContext(), stream);
    }

    @Override
    public FingerprintAttributePreparator getPreparator(IceContext context) {
        return new FingerprintAttributePreparator(context.getChooser(), this);
    }

    @Override
    public FingerprintAttributeSerializer getSerializer(IceContext context) {
        return new FingerprintAttributeSerializer(this);
    }
}
