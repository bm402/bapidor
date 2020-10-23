package com.github.bncrypted.bapidor.model.exported;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class ExportedDefinition {
    private String base;
    private ExportedAuthDetails auth;
    private Map<String, ExportedVariables> vars;
    private ExportedApiDetails api;
}
