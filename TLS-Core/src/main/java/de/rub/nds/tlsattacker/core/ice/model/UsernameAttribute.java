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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.UsernameAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.UsernameAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.UsernameAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.UsernameAttributeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
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
    public UsernameAttributeHandler getHandler(Context context) {
        return new UsernameAttributeHandler(context.getIceContext());
    }

    @Override
    public UsernameAttributeParser getParser(Context context, InputStream stream) {
        return new UsernameAttributeParser(context.getIceContext(), stream);
    }

    @Override
    public UsernameAttributePreparator getPreparator(Context context) {
        return new UsernameAttributePreparator(context.getChooser(), this);
    }

    @Override
    public UsernameAttributeSerializer getSerializer(Context context) {
        return new UsernameAttributeSerializer(this);
    }
}
