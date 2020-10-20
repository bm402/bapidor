package com.github.bncrypted.bapidor.api;

import com.github.bncrypted.bapidor.model.AuthDetails;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Vars;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Getter
public enum ApiStore {
    INSTANCE;

    @Setter
    private boolean isListening;

    @Setter
    private String baseUri;

    @Setter
    private AuthDetails authDetails;

    private Map<String, Vars> vars;
    private Map<String, EndpointDetails> endpoints;

    ApiStore() {
        isListening = false;
        vars = new HashMap<>();
        endpoints = new HashMap<>();
    }

    public void addEndpointDetails(String endpointCode, EndpointDetails endpointDetails) {
        if (endpoints.containsKey(endpointCode)) {
            if (!endpoints.get(endpointCode).isEvaluated()) {
                evaluateEndpoint();
            }
        } else {
            endpoints.put(endpointCode, endpointDetails);
        }
    }

    public void reset() {
        setBaseUri(null);
        setAuthDetails(null);
        vars = new HashMap<>();
        endpoints = new HashMap<>();
    }

    private void evaluateEndpoint() {

    }
}
