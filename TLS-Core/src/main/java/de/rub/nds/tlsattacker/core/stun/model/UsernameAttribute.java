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
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.UsernameAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.UsernameAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.UsernameAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.UsernameAttributeSerializer;
import java.io.InputStream;

public class UsernameAttribute extends StunAttribute {

    private ModifiableString username;

    public UsernameAttribute() {
        super(StunAttributeType.USERNAME);
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
    public UsernameAttributePreparator getPreparator(IceContext context) {
        return new UsernameAttributePreparator(context.getChooser(), this);
    }

    @Override
    public UsernameAttributeSerializer getSerializer(IceContext context) {
        return new UsernameAttributeSerializer(this);
    }
}
