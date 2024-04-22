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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.UsernameAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.UsernameAttributeParser;
import java.io.InputStream;

public class UsernameAttribute extends StunAttribute {

    private ModifiableString username;

    public UsernameAttribute() {
        super();
    }

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(ModifiableString username) {
        this.username = username;
    }

    public void setUsername(String username) {
        this.username = ModifiableVariableFactory.safelySetValue(this.username, username);
    }

    @Override
    public UsernameAttributeHandler getHandler(IceContext context) {
        return new UsernameAttributeHandler(context);
    }

    @Override
    public UsernameAttributeParser getParser(IceContext context, InputStream stream) {
        return new UsernameAttributeParser(context, stream);
    }

    @Override
    public Preparator<?> getPreparator(IceContext context) {}

    @Override
    public Serializer<?> getSerializer(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }
}
