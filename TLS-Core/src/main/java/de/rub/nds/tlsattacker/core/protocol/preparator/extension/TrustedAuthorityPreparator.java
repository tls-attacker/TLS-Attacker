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

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TrustedAuthorityPreparator extends Preparator<TrustedAuthority> {

    private final TrustedAuthority object;

    public TrustedAuthorityPreparator(Chooser chooser, TrustedAuthority object) {
        super(chooser, object);
        this.object = object;
    }

    @Override
    public void prepare() {
        object.setIdentifierType(object.getPreparatorIdentifierType());
        if (object.getPreparatorSha1Hash() != null) {
            object.setSha1Hash(object.getPreparatorSha1Hash());
        }
        if (object.getPreparatorDistinguishedNameLength() != null) {
            object.setDistinguishedNameLength(object.getPreparatorDistinguishedNameLength());
        }
        if (object.getPreparatorDistinguishedName() != null) {
            object.setDistinguishedName(object.getPreparatorDistinguishedName());
        }
    }

}
