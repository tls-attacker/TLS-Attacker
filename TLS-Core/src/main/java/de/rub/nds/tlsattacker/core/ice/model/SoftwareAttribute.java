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
import de.rub.nds.tlsattacker.core.ice.handler.SoftwareAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.SoftwareAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.SoftwareAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.SoftwareAttributeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

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
        this.softwareString =
                ModifiableVariableFactory.safelySetValue(this.softwareString, softwareString);
    }

    @Override
    public SoftwareAttributeHandler getHandler(Context context) {
        return new SoftwareAttributeHandler(context);
    }

    @Override
    public SoftwareAttributeParser getParser(Context context, InputStream stream) {
        return new SoftwareAttributeParser(context, stream);
    }

    @Override
    public SoftwareAttributePreparator getPreparator(Context context) {
        return new SoftwareAttributePreparator(context.getChooser(), this);
    }

    @Override
    public SoftwareAttributeSerializer getSerializer(Context context) {
        return new SoftwareAttributeSerializer(this);
    }
}
