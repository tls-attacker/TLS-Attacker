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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.handler.SoftwareAttributeHandler;
import de.rub.nds.tlsattacker.core.stun.parser.SoftwareAttributeParser;
import de.rub.nds.tlsattacker.core.stun.preparator.SoftwareAttributePreparator;
import de.rub.nds.tlsattacker.core.stun.serializer.SoftwareAttributeSerializer;

public class SoftwareAttribute extends StunAttribute {

    private ModifiableString softwareString;

    public SoftwareAttribute() {
        super(StunAttributeType.SOFTWARE);
    }

    public void setSoftwareString(ModifiableString softwareString) {
        this.softwareString = softwareString;
    }

    public ModifiableString getSoftwareString() {
        return softwareString;
    }

    public void setSoftwareString(String softwareString) {
        this.softwareString = ModifiableVariableFactory.safelySetValue(this.softwareString, softwareString);
    }

    @Override
    public SoftwareAttributeHandler getHandler(IceContext context) {
        return new SoftwareAttributeHandler(context);
    }

    @Override
    public SoftwareAttributeParser getParser(IceContext context, InputStream stream) {
        return new SoftwareAttributeParser(context, stream);
    }

    @Override
    public SoftwareAttributePreparator getPreparator(IceContext context) {
        return new SoftwareAttributePreparator(context.getChooser(), this);
    }

    @Override
    public SoftwareAttributeSerializer getSerializer(IceContext context) {
        return new SoftwareAttributeSerializer(this);
    }
}
