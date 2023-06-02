/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class EncryptedClientHelloExtensionPreparator
        extends ExtensionPreparator<EncryptedClientHelloExtensionMessage> {

    private final EncryptedClientHelloExtensionMessage msg;

    public EncryptedClientHelloExtensionPreparator(
            Chooser chooser, EncryptedClientHelloExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        // the clienthellotype has to be set in the message constructor because it relies on the
        // context
        if (msg.getEchClientHelloType() == EchClientHelloType.OUTER) {
            // inner client hello contains no data in the ech extension
            prepareHpkeCipherSuite(msg);
            prepareConfigId(msg);
            prepareEnc();
            preparePayload();
        }
    }

    public void prepareAfterParse() {}

    private void prepareConfigId(EncryptedClientHelloExtensionMessage msg) {
        msg.setConfigId(chooser.getEchConfig().getConfigId());
    }

    private void prepareEnc() {
        // TODO: save this somewhere else than config, context probably
        msg.setEncLength(chooser.getEchClientKeyShareEntry().getPublicKeyLength());
        msg.setEnc(chooser.getEchClientKeyShareEntry().getPublicKey());
    }

    private void preparePayload() {
        // is being set by EncryptedClientHelloPreparator, unintuitive but the ECH contructing
        // necessitates this
        if (msg.getPayload() == null) {
            msg.setPayload(new byte[] {});
            msg.setPayloadLength(0);
        }
    }

    private void prepareHpkeCipherSuite(EncryptedClientHelloExtensionMessage msg) {
        msg.setHpkeCipherSuite(chooser.getEchConfig().getHpkeCipherSuites().get(0));
    }
}
