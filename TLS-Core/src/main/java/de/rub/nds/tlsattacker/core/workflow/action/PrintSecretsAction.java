/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "PrintSecrets")
public class PrintSecretsAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public PrintSecretsAction() {}

    public PrintSecretsAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getContext(connectionAlias).getTlsContext();
        StringBuilder builder = new StringBuilder("\n\nContext: " + context);
        builder.append("\n  (Record Layer) ");
        if (context.getSelectedCipherSuite() == null) {
            builder.append("\n  CipherSuite: null");
        } else {
            builder.append("\n  CipherSuite: ").append(context.getSelectedCipherSuite().name());
        }

        builder.append("\n  (RSA Key Exchange) ");
        if (context.getChooser()
                        .getContext()
                        .getTlsContext()
                        .getServerX509Context()
                        .getSubjectRsaPublicExponent()
                == null) {
            builder.append("\n  ServerRsaPublicKey (chooser): null");
        } else {
            builder.append("\n  ServerRsaPublicKey (chooser): ");
            builder.append(
                    context.getChooser()
                            .getContext()
                            .getTlsContext()
                            .getServerX509Context()
                            .getSubjectRsaPublicExponent());
        }
        if (context.getChooser()
                        .getContext()
                        .getTlsContext()
                        .getServerX509Context()
                        .getSubjectRsaModulus()
                == null) {
            builder.append("\n  ServerRsaModulus(chooser): null");
        } else {
            builder.append("\n  ServerRsaModulus (chooser): ");
            builder.append(
                    toHex(
                            DataConverter.bigIntegerToByteArray(
                                    context.getChooser()
                                            .getContext()
                                            .getTlsContext()
                                            .getServerX509Context()
                                            .getSubjectRsaModulus())));
        }

        builder.append("\n\n  (Handshake) ");
        builder.append("\n  Client Random: ").append(toHex(context.getClientRandom()));
        builder.append("\n  Server Random: ").append(toHex(context.getServerRandom()));
        builder.append("\n  PreMasterSecret: ").append(toHex(context.getPreMasterSecret()));
        builder.append("\n  MasterSecret: ").append(toHex(context.getMasterSecret()));

        if (context.getLastClientVerifyData() == null) {
            builder.append("\n  LastClientVerifyData: null");
        } else {
            builder.append("\n  LastClientVerifyData: ")
                    .append(toHex(context.getLastClientVerifyData()));
        }
        if (context.getLastServerVerifyData() == null) {
            builder.append("\n  LastServerVerifyData: null");
        } else {
            builder.append("\n  LastServerVerifyData: ")
                    .append(toHex(context.getLastServerVerifyData()));
        }

        LOGGER.info(builder.append("\n").toString());
    }

    private String toHex(byte[] bytes) {
        return DataConverter.bytesToRawHexString(bytes);
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {}
}
