package com.github.bncrypted.bapidor.api;

import com.github.bncrypted.bapidor.model.AuthDetails;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Privilege;
import com.github.bncrypted.bapidor.model.Vars;
import com.github.bncrypted.bapidor.request.RequestDiffer;
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
public class ApiStore {

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

    public ApiStore() {
        isListening = false;
        vars = new HashMap<>();
        endpoints = new HashMap<>();
        commonApiObjects = loadCommonApiObjects();
        varId = new AtomicInteger(0);
    }

    public void addEndpointDetails(String endpointCode, EndpointDetails newEndpointDetails) {
        if (endpoints.containsKey(endpointCode)) {
            EndpointDetails curEndpointDetails = endpoints.get(endpointCode);
            if (curEndpointDetails.getPrivilege() != newEndpointDetails.getPrivilege() && !curEndpointDetails.isEvaluated()) {
                if (curEndpointDetails.getPrivilege() == Privilege.HIGH) {
                    evaluateEndpoint(endpointCode, curEndpointDetails, newEndpointDetails);
                } else {
                    evaluateEndpoint(endpointCode, newEndpointDetails, curEndpointDetails);
                }
            }
        } else {
            endpoints.put(endpointCode, newEndpointDetails);
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

    private void evaluateEndpoint(String endpointCode,
                                  EndpointDetails highPrivilegedEndpointDetails,
                                  EndpointDetails lowPrivilegedEndpointDetails) {

        RequestDiffer requestDiffer = new RequestDiffer(this);
        String evaluatedMethod = highPrivilegedEndpointDetails.getMethod();
        String evaluatedPath = requestDiffer.createPathWithVarIds(highPrivilegedEndpointDetails.getPath(),
                lowPrivilegedEndpointDetails.getPath());
        Map<String, String> evaluatedHeaders = requestDiffer.sanitiseHighPrivilegedHeaders(
                highPrivilegedEndpointDetails.getHeaders());
        Map<String, String> evaluatedRequestParams = requestDiffer.createRequestParamsWithVarIds(
                highPrivilegedEndpointDetails.getRequestParams(), lowPrivilegedEndpointDetails.getRequestParams());
        Map<String, Object> evaluatedBodyParams = requestDiffer.createBodyParamsWithVarIds(
                highPrivilegedEndpointDetails.getBodyParams(), lowPrivilegedEndpointDetails.getBodyParams());

        EndpointDetails evaluatedEndpointDetails = EndpointDetails.builder()
                .method(evaluatedMethod)
                .path(evaluatedPath)
                .headers(evaluatedHeaders)
                .requestParams(evaluatedRequestParams)
                .bodyParams(evaluatedBodyParams)
                .isEvaluated(true)
                .build();

        endpoints.put(endpointCode, evaluatedEndpointDetails);

        Map<String, Vars> evaluatedVars = requestDiffer.getVars();
        vars.putAll(evaluatedVars);
    }
}
