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
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.PriorityAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.PriorityAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.PriorityAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.PriorityAttributeSerializer;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

import java.io.InputStream;

public class PriorityAttribute extends StunAttribute {

    /** This is an unsigned 4 byte integer */
    private ModifiableLong priority;

    public PriorityAttribute() {
        super(StunAttributeType.PRIORITY);
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
