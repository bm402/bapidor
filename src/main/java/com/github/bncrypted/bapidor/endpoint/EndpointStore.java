package com.github.bncrypted.bapidor.endpoint;

import com.github.bncrypted.bapidor.model.EndpointDetails;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

public enum EndpointStore {
    INSTANCE;

    @Getter
    @Setter
    private String baseUri;

    @Getter
    private final Map<String, EndpointDetails> store;

    EndpointStore() {
        store = new HashMap<>();
    }

    public void addEndpointDetailsToStore(String endpointCode, EndpointDetails endpointDetails) {
        if (store.containsKey(endpointCode)) {
            if (!store.get(endpointCode).isEvaluated()) {
                evaluateEndpoint();
            }
        } else {
            store.put(endpointCode, endpointDetails);
        }
    }

    private void evaluateEndpoint() {

    }
}
