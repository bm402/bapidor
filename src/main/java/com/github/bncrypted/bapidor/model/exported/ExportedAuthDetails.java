package com.github.bncrypted.bapidor.model.exported;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ExportedAuthDetails {
    private String header_name;
    private String header_value_prefix;
    private String high_privileged_access_token;
    private String low_privileged_access_token;
}
