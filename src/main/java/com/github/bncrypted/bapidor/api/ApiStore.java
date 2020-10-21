package com.github.bncrypted.bapidor.api;

import com.github.bncrypted.bapidor.model.AuthDetails;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Vars;
import lombok.Getter;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

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

    private final AtomicInteger varId;
    private final Set<String> commonApiObjects;

    ApiStore() {
        isListening = false;
        vars = new HashMap<>();
        endpoints = new HashMap<>();
        commonApiObjects = loadCommonApiObjects();
        varId = new AtomicInteger(0);

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

    public boolean isCommonApiObject(String word) {
        return commonApiObjects.contains(word.toLowerCase());
    }

    public String getNextVarId() {
        return "var" + varId.getAndIncrement();
    }

    public void reset() {
        setBaseUri(null);
        setAuthDetails(null);
        vars = new HashMap<>();
        endpoints = new HashMap<>();
    }

    private Set<String> loadCommonApiObjects() {
        Set<String> apiObjects = new HashSet<>();
        ClassLoader classLoader = ApiStore.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream("api-objects.txt")) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            while (reader.ready()) {
                String apiObject = reader.readLine().toLowerCase();
                apiObjects.add(apiObject);
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return apiObjects;
    }

    private void evaluateEndpoint() {

    }
}
