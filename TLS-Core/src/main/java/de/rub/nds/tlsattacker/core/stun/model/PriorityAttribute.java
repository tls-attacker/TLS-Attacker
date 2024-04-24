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
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.PriorityAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.PriorityAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.PriorityAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.PriorityAttributeSerializer;
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
    public PriorityAttributeHandler getHandler(IceContext context) {
        return new PriorityAttributeHandler(context);
    }

    @Override
    public PriorityAttributeParser getParser(IceContext context, InputStream stream) {
        return new PriorityAttributeParser(context, stream);
    }

    @Override
    public PriorityAttributePreparator getPreparator(IceContext context) {
        return new PriorityAttributePreparator(context.getChooser(), this);
    }

    @Override
    public PriorityAttributeSerializer getSerializer(IceContext context) {
        return new PriorityAttributeSerializer(this);
    }
}
