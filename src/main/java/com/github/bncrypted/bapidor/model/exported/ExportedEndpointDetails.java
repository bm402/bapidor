package com.github.bncrypted.bapidor.model.exported;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class ExportedEndpointDetails {
    private String method;
    private boolean is_delete;
    private String content_type;
    private Map<String, String> headers;
    private Map<String, String> request_params;
    private Map<String, Object> body_params;

    public boolean getIs_delete() {
        return is_delete;
    }
}
