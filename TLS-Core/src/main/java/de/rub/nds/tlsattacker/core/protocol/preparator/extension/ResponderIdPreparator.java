/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ResponderIdPreparator extends Preparator<ResponderId> {

    private final ResponderId object;

    public ResponderIdPreparator(Chooser chooser, ResponderId object) {
        super(chooser, object);
        this.object = object;
    }

    @Override
    public void prepare() {
        object.setId(object.getIdConfig());
        object.setIdLength(object.getIdLengthConfig());
    }

}
