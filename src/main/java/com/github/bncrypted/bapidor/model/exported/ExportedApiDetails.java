package com.github.bncrypted.bapidor.model.exported;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class ExportedApiDetails {
    private List<String> methods;
    private Map<String, String> headers;
    private Map<String, List<ExportedEndpointDetails>> endpoints;
}
