package com.github.bncrypted.bapidor.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.Privilege;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RequestParser {
    
    private final ApiStore apiStore;
    
    public RequestParser(ApiStore apiStore) {
        this.apiStore = apiStore;
    }

    public String getEndpointCode(String endpointMethod, String endpointName) {
        String[] endpointNameComponents = endpointName.split("/");
        StringBuilder sanitisedEndpointName = new StringBuilder();

        for (int i = 1; i < endpointNameComponents.length; i++) {
            sanitisedEndpointName.append("/");

            if (apiStore.isCommonApiObject(endpointNameComponents[i])) {
                sanitisedEndpointName.append(endpointNameComponents[i]);
            } else if (endpointNameComponents[i].contains(".") &&
                    isComponentWithSeparatorValid(endpointNameComponents[i], "\\.")) {
                sanitisedEndpointName.append(endpointNameComponents[i]);
            } else if (endpointNameComponents[i].contains("-") &&
                    isComponentWithSeparatorValid(endpointNameComponents[i], "-")) {
                sanitisedEndpointName.append(endpointNameComponents[i]);
            } else if (endpointNameComponents[i].contains("_") &&
                    isComponentWithSeparatorValid(endpointNameComponents[i], "_")) {
                sanitisedEndpointName.append(endpointNameComponents[i]);
            }
        }

        return endpointMethod + sanitisedEndpointName.toString();
    }

    private boolean isComponentWithSeparatorValid(String endpointComponent, String separator) {
        boolean isValid = false;
        String[] components = endpointComponent.split(separator);
        for (String component : components) {
            if (apiStore.isCommonApiObject(component)) {
                isValid = true;
            }
        }
        return isValid;
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
        } else if (authHeaderValue.contains(apiStore.getAuthDetails().getHighPrivilegedToken())) {
            return Privilege.HIGH;
        } else if (authHeaderValue.contains(apiStore.getAuthDetails().getLowPrivilegedToken())) {
            return Privilege.LOW;
        }
        return Privilege.NONE;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonBodyParams(byte[] body) throws IOException {
        return new ObjectMapper().readValue(body, Map.class);
    }
}
