/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.stun.IceChooser;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class StunAttributePreparator<AttributeT extends StunAttribute>
        extends Preparator<AttributeT> {

    protected IceChooser iceChooser;

    public StunAttributePreparator(Chooser chooser, AttributeT attribute) {
        super(chooser, attribute);
        this.iceChooser = chooser.getIceChooser();
    }

    @Override
    public final void prepare() {
        getObject().setAttributeType(getObject().getType().getValue());
        prepareContent();
        getObject()
                .setBody(
                        getObject()
                                .getSerializer(chooser.getContext().getIceContext())
                                .serializeAttributeContent());
        getObject().setAttributeLength(getObject().getBody().getValue().length);
        int paddingLength = (IceByteLengths.STUN_ATTRIBUTE_ALIGNMENT - getObject().getAttributeLength().getValue())
                % IceByteLengths.STUN_ATTRIBUTE_ALIGNMENT;
        if (paddingLength < 0) {
            paddingLength = 0;
        }
        getObject().setPadding(new byte[paddingLength]);
    }

    public abstract void prepareContent();
}
