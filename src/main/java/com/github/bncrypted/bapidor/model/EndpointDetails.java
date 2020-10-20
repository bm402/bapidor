package com.github.bncrypted.bapidor.model;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class EndpointDetails {
    private final String method;
    private String path;
    private Map<String, String> headers;
    private Map<String, String> requestParams;
    private Map<String, Object> bodyParams;
    private final Privilege privilege;
    @Builder.Default
    private boolean isEvaluated = false;
}
