/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class TrustedAuthorityPreparator extends Preparator<TrustedAuthority> {

    private final TrustedAuthority object;

    public TrustedAuthorityPreparator(Chooser chooser, TrustedAuthority object) {
        super(chooser, object);
        this.object = object;
    }

    @Override
    public void prepare() {
        object.setIdentifierType(object.getIdentifierTypeConfig());
        if (object.getSha1HashConfig() != null) {
            object.setSha1Hash(object.getSha1HashConfig());
        }
        if (object.getDistinguishedNameLengthConfig() != null) {
            object.setDistinguishedNameLength(object.getDistinguishedNameLengthConfig());
        }
        if (object.getDistinguishedNameConfig() != null) {
            object.setDistinguishedName(object.getDistinguishedNameConfig());
        }
    }

}
