package com.github.bncrypted.bapidor.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.bncrypted.bapidor.model.AuthDetails;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Privilege;
import com.github.bncrypted.bapidor.model.Vars;
import com.github.bncrypted.bapidor.model.exported.ExportedApiDetails;
import com.github.bncrypted.bapidor.model.exported.ExportedAuthDetails;
import com.github.bncrypted.bapidor.model.exported.ExportedDefinition;
import com.github.bncrypted.bapidor.model.exported.ExportedEndpointDetails;
import com.github.bncrypted.bapidor.model.exported.ExportedVariables;
import com.github.bncrypted.bapidor.request.RequestDiffer;
import lombok.Getter;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
    @Setter
    private OutputStream stdout;

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

    public void save(String filepath) {
        ExportedDefinition baseDefinition = buildBaseDefinition();
        ExportedDefinition evaluatedDefinition = addEvaluatedEndpointsToDefinition(baseDefinition);

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

        try {
            mapper.writeValue(new File(filepath), evaluatedDefinition);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        ExportedDefinition unevaluatedDefinition = addUnevaluatedEndpointsToDefinition(baseDefinition);
        String[] filepathComponents = filepath.split("\\.");
        StringBuilder filename = new StringBuilder();
        for (int i = 0; i < filepathComponents.length - 1; i++) {
            filename.append(filepathComponents[i]);
            filename.append(".");
        }
        String unevaluatedFilepath = filename.toString() + "unevaluated." +
                filepathComponents[filepathComponents.length-1];

        try {
            mapper.writeValue(new File(unevaluatedFilepath), unevaluatedDefinition);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private ExportedDefinition buildBaseDefinition() {

        ExportedAuthDetails exportedAuthDetails = ExportedAuthDetails.builder()
                .header_name(authDetails.getHeaderName())
                .header_value_prefix(authDetails.getHeaderValuePrefix())
                .high_privileged_access_token(authDetails.getHighPrivilegedToken())
                .low_privileged_access_token(authDetails.getLowPrivilegedToken())
                .build();

        Map<String, ExportedVariables> exportedVars = new HashMap<>();
        vars.forEach((varId, varDetails) -> {
            ExportedVariables exportedVar = ExportedVariables.builder()
                    .high(varDetails.getHigh())
                    .low(varDetails.getLow())
                    .alias(varDetails.getAlias())
                    .build();
            exportedVars.put(varId, exportedVar);
        });

        return ExportedDefinition.builder()
                .base(baseUri)
                .auth(exportedAuthDetails)
                .vars(exportedVars)
                .build();
    }

    private ExportedDefinition addEvaluatedEndpointsToDefinition(ExportedDefinition definition) {
        Map<String, List<ExportedEndpointDetails>> exportedEndpoints = new HashMap<>();
        endpoints.forEach((endpointCode, endpointDetails) -> {
            if (endpointDetails.isEvaluated() && !endpointDetails.isStatic()) {

                String endpoint = endpointDetails.getPath();
                if (!exportedEndpoints.containsKey(endpoint)) {
                    exportedEndpoints.put(endpoint, new ArrayList<>());
                }

                ExportedEndpointDetails exportedEndpointDetails = ExportedEndpointDetails.builder()
                        .method(endpointDetails.getMethod())
                        .content_type(convertContentType(endpointDetails.getHeaders().get("Content-Type")))
                        .headers(endpointDetails.getHeaders())
                        .request_params(endpointDetails.getRequestParams())
                        .body_params(endpointDetails.getBodyParams())
                        .build();

                exportedEndpoints.get(endpoint).add(exportedEndpointDetails);
            }
        });

        ExportedApiDetails exportedApiDetails = ExportedApiDetails.builder()
                .endpoints(exportedEndpoints)
                .build();

        definition.setApi(exportedApiDetails);
        return definition;
    }

    private ExportedDefinition addUnevaluatedEndpointsToDefinition(ExportedDefinition definition) {
        Map<String, List<ExportedEndpointDetails>> exportedEndpoints = new HashMap<>();
        endpoints.forEach((endpointCode, endpointDetails) -> {
            if (!endpointDetails.isEvaluated()) {

                String endpoint = endpointDetails.getPath();
                if (!exportedEndpoints.containsKey(endpoint)) {
                    exportedEndpoints.put(endpoint, new ArrayList<>());
                }

                ExportedEndpointDetails exportedEndpointDetails = ExportedEndpointDetails.builder()
                        .method(endpointDetails.getMethod())
                        .content_type(convertContentType(endpointDetails.getHeaders().get("Content-Type")))
                        .headers(endpointDetails.getHeaders())
                        .request_params(endpointDetails.getRequestParams())
                        .body_params(endpointDetails.getBodyParams())
                        .build();

                exportedEndpoints.get(endpoint).add(exportedEndpointDetails);
            }
        });

        ExportedApiDetails exportedApiDetails = ExportedApiDetails.builder()
                .endpoints(exportedEndpoints)
                .build();

        definition.setApi(exportedApiDetails);
        return definition;
    }

    private String convertContentType(String contentType) {
        if (contentType == null) {
            return null;
        }
        String encodedContentType;
        switch (contentType) {
            case "application/json":
                encodedContentType = "JSON";
                break;
            case "application/x-www-form-urlencoded":
                encodedContentType = "FORM-DATA";
                break;
            default:
                encodedContentType = contentType;
                break;
        }
        return encodedContentType;
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

        Map<String, Vars> evaluatedVars = requestDiffer.getVars();
        if (evaluatedVars.size() == 0) {
            evaluatedEndpointDetails.setStatic(true);
        } else {
            vars.putAll(evaluatedVars);
        }

        endpoints.put(endpointCode, evaluatedEndpointDetails);
    }
}
