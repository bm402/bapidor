package com.github.bncrypted.bapidor.request;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestParser {

    public String getEndpointCode(String topLineOfHeader) {
        String[] endpointComponents = topLineOfHeader.split(" ");
        String endpointMethod = endpointComponents[0];
        String endpointName = endpointComponents[1];

        int startOfRequestParams = endpointComponents[1].indexOf("?");
        if (startOfRequestParams > -1) {
            endpointName = endpointName.substring(0, startOfRequestParams);
        }

        endpointName = removeUUIDsFromEndpointName(endpointName);
        endpointName = removeIntegersFromEndpointName(endpointName);

        return endpointMethod + endpointName;
    }

    private String removeUUIDsFromEndpointName(String endpointName) {
        StringBuilder endpointNameWithoutUUIDs = new StringBuilder();
        int stringBuilderStartIndex = 0;
        int matcherStartIndex = 0;

        Pattern pattern = Pattern.compile("([a-f0-9]{8}(-[a-f0-9]{4}){4}[a-f0-9]{8})",
                Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(endpointName);

        while (matcher.find(matcherStartIndex)) {
            int curMatcherIndex = matcher.start();
            endpointNameWithoutUUIDs.append(
                    endpointName, stringBuilderStartIndex, curMatcherIndex);
            stringBuilderStartIndex = curMatcherIndex + 36;
            matcherStartIndex = curMatcherIndex + 36;
        }

        if (stringBuilderStartIndex < endpointName.length()) {
            endpointNameWithoutUUIDs.append(
                    endpointName, stringBuilderStartIndex, endpointName.length());
        }

        return endpointNameWithoutUUIDs.toString();
    }

    private String removeIntegersFromEndpointName(String endpointName) {
        StringBuilder endpointNameWithoutIntegers = new StringBuilder();
        for (int i = 0; i < endpointName.length(); i++) {
            char curChar = endpointName.charAt(i);
            if (curChar - '0' < 0 || curChar - '0' > 9) {
                endpointNameWithoutIntegers.append(curChar);
            }
        }
        return endpointNameWithoutIntegers.toString();
    }
}
