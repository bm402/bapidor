package com.github.bncrypted.bapidor.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.Privilege;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RequestParser {

    public String getEndpointCode(String endpointMethod, String endpointName) {
        endpointName = removeUUIDsFromEndpointName(endpointName);
        endpointName = removeIntegersFromEndpointName(endpointName);
        return endpointMethod + endpointName;
    }

    public Map<String, String> parseHeaders(List<String> headersList) {
        Map<String, String> headers = new HashMap<>();
        headersList.remove(0);
        headersList.forEach(header -> {
            String[] headerComponents = header.split(":");
            String headerName = headerComponents[0].strip();
            StringBuilder headerValue = new StringBuilder();
            for (int i = 1; i < headerComponents.length; i++) {
                headerValue.append(headerComponents[i]);
            }
            headers.put(headerName, headerValue.toString().strip());
        });
        return headers;
    }

    public Map<String, String> parseRequestParams(String requestParamsStr) {
        Map<String, String> requestParams = new HashMap<>();
        if (requestParamsStr == null) {
            return requestParams;
        }

        String[] paramPairs = requestParamsStr.split("&");
        for (String paramPair : paramPairs) {
            String[] paramComponents = paramPair.split("=");
            if (paramComponents.length == 2) {
                requestParams.put(paramComponents[0], paramComponents[1]);
            } else {
                requestParams.put(paramComponents[0], "");
            }
        }
        return requestParams;
    }

    public Map<String, Object> parseBodyParams(byte[] request, int bodyOffset, String contentType) {
        Map<String, Object> bodyParams = new HashMap<>();
        if (contentType == null) {
            return bodyParams;
        }
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);

        switch (contentType) {
            case "application/json":
                try {
                    bodyParams = parseJsonBodyParams(body);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                break;
        }

        return bodyParams;
    }

    public Privilege findPrivilege(String authHeaderValue) {
        if (authHeaderValue == null) {
            return Privilege.NONE;
        }
        if (authHeaderValue.contains(ApiStore.INSTANCE.getAuthDetails().getHighPrivilegedToken())) {
            return Privilege.HIGH;
        } else if (authHeaderValue.contains(ApiStore.INSTANCE.getAuthDetails().getLowPrivilegedToken())) {
            return Privilege.LOW;
        }
        return Privilege.NONE;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonBodyParams(byte[] body) throws IOException {
        return new ObjectMapper().readValue(body, Map.class);
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
