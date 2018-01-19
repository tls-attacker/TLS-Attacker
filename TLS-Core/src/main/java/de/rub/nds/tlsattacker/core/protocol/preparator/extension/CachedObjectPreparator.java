/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class CachedObjectPreparator extends Preparator<CachedObject> {

    private final CachedObject object;

    public CachedObjectPreparator(Chooser chooser, CachedObject object) {
        super(chooser, object);
        this.object = object;
    }

    @Override
    public void prepare() {
        object.setCachedInformationType(object.getCachedInformationTypeConfig());
        if (object.getHashValueLengthConfig() != null) {
            object.setHashValueLength(object.getHashValueLengthConfig());
        }
        if (object.getHashValueConfig() != null) {
            object.setHashValue(object.getHashValueConfig());
        } else {
            object.setHashValue((ModifiableByteArray) null);
        }
    }

}
