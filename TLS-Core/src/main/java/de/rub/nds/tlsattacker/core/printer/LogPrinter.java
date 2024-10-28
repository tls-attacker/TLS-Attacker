/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.printer;

import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import java.util.List;
import java.util.StringJoiner;
import org.apache.logging.log4j.Level;

public class LogPrinter {

    private LogPrinter() {}

    public static String toHumanReadableOneLine(
            List<LayerConfiguration<?>> layerConfigurations, Level level) {
        StringBuilder stringBuilder = new StringBuilder();
        for (LayerConfiguration<?> layerConfiguration : layerConfigurations) {
            if (layerConfiguration.shouldBeLogged(level)) {
                stringBuilder.append(layerConfiguration.toCompactString());
                stringBuilder.append(" ");
            }
        }
        return stringBuilder.toString().trim();
    }

    public static String toHumanReadableMultiLine(
            List<LayerConfiguration<?>> layerConfigurations, Level level) {
        StringBuilder stringBuilder = new StringBuilder();
        for (LayerConfiguration<?> layerConfiguration : layerConfigurations) {
            if (layerConfiguration.shouldBeLogged(level)) {
                stringBuilder.append(layerConfiguration.toCompactString());
                stringBuilder.append(" ");
            }
        }
        return stringBuilder.toString().trim();
    }

    public static String toHumanReadableMultiLine(
            LayerStackProcessingResult processingResult, Level level) {
        StringBuilder stringBuilder = new StringBuilder();
        for (LayerProcessingResult<?> result : processingResult.getLayerProcessingResultList()) {
            stringBuilder.append(result.toCompactString());
            stringBuilder.append(System.lineSeparator());
        }
        stringBuilder.trimToSize();
        return stringBuilder.toString();
    }

    public static String toHumanReadableContainerList(
            List<DataContainer> containerList, Level level) {
        if (containerList == null) {
            return "null";
        }
        if (containerList.isEmpty()) {
            return "empty";
        }

        StringBuilder sb = new StringBuilder();
        StringJoiner joiner = new StringJoiner(", ");
        for (DataContainer container : containerList) {
            joiner.add(container.toCompactString());
        }
        sb.trimToSize();
        return sb.toString();
    }

    public static String toHumanReadableMultiLineContainerListArray(
            List<List<DataContainer>> containerListList, Level level) {
        StringBuilder sb = new StringBuilder();
        StringJoiner joiner = new StringJoiner(", ");
        for (List<DataContainer> containerList : containerListList) {
            if (containerList != null) {
                for (DataContainer container : containerList) {
                    joiner.add(container.toCompactString());
                }
            }
            sb.append(joiner.toString());
            sb.append(System.lineSeparator());
        }
        sb.trimToSize();
        return sb.toString();
    }
}
