/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PskSet;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;

public class PSKBinderPreparator extends Preparator<PSKBinder> {

    private final PSKBinder pskBinder;
    private final PskSet pskSet;

    public PSKBinderPreparator(Chooser chooser, PSKBinder pskBinder, PskSet pskSet) {
        super(chooser, pskBinder);
        this.pskBinder = pskBinder;
        this.pskSet = pskSet;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing PSKBinder");
        prepareBinderValue();
    }

    private void prepareBinderValue() {
        try {
            HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(pskSet.getCipherSuite());
            int macLen = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();

            pskBinder.setBinderEntry(new byte[macLen]);
            pskBinder.setBinderEntryLength(pskBinder.getBinderEntry().getValue().length);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PSKBinderPreparator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
