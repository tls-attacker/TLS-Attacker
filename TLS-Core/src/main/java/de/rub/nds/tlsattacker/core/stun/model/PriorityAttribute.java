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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.stun.IceContext;
import java.io.InputStream;

public class PriorityAttribute extends StunAttribute {

    /** This is an unsigned 4 byte integer */
    private ModifiableLong priority;

    public PriorityAttribute() {
        super();
    }

    public ModifiableLong getPriority() {
        return priority;
    }

    public void setPriority(ModifiableLong priority) {
        this.priority = priority;
    }

    public void setPriority(long priority) {
        this.priority = ModifiableVariableFactory.safelySetValue(this.priority, priority);
    }

    @Override
    public Handler<?> getHandler(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Parser<?> getParser(IceContext context, InputStream stream) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Preparator<?> getPreparator(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Serializer<?> getSerializer(IceContext context) {
        // TODO Auto-generated method stub
        return null;
    }
}
