/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EchConfigParser;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;

public class EchDelegate extends Delegate {

    @Parameter(names = "-echConfig", required = false, description = "EchConfig in Hex Bytes")
    private String echConfig =
            "003EFE0D003AB8002000205611F61F4F5F5C801C60009DA68DD0EB0DD5DBA8FF33C32D5025D7FFADF5DC6F000400010001000B6578616D706C652E636F6D0000";

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        EchConfigParser parser =
                new EchConfigParser(
                        new ByteArrayInputStream(ArrayConverter.hexStringToByteArray(echConfig)),
                        new TlsContext(config));
        List<EchConfig> echConfigList = new LinkedList<>();
        parser.parse(echConfigList);
        config.setDefaultEchConfig(echConfigList.get(0));
    }

    public String getEchConfig() {
        return echConfig;
    }

    public void setEchConfig(String echConfig) {
        this.echConfig = echConfig;
    }
}
