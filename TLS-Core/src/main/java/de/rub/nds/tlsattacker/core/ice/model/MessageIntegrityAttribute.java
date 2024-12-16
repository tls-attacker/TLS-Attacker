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
import de.rub.nds.tlsattacker.core.ice.handler.MessageIntegrityHandler;
import de.rub.nds.tlsattacker.core.ice.parser.MessageIntegrityParser;
import de.rub.nds.tlsattacker.core.ice.preparator.MessageIntegrityPreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.MessageIntegritySerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class MessageIntegrityAttribute extends StunAttribute {

    /** 8 byte */
    private ModifiableByteArray hmac;

    public MessageIntegrityAttribute() {
        super(StunAttributeType.MESSAGE_INTEGRITY);
    }

    public ModifiableByteArray getHmac() {
        return hmac;
    }

    public void setHmac(ModifiableByteArray hmac) {
        this.hmac = hmac;
    }

    public void setHmac(byte[] hmac) {
        this.hmac = ModifiableVariableFactory.safelySetValue(this.hmac, hmac);
    }

    @Override
    public MessageIntegrityHandler getHandler(Context context) {
        return new MessageIntegrityHandler(context.getIceContext());
    }

    @Override
    public MessageIntegrityParser getParser(Context context, InputStream stream) {
        return new MessageIntegrityParser(context.getIceContext(), stream);
    }

    @Override
    public MessageIntegrityPreparator getPreparator(Context context) {
        return new MessageIntegrityPreparator(context.getChooser(), this);
    }

    @Override
    public MessageIntegritySerializer getSerializer(Context context) {
        return new MessageIntegritySerializer(this);
    }
}
