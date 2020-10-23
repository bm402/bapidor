package com.github.bncrypted.bapidor.model.exported;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ExportedVariables {
    private Object high;
    private Object low;
    private String alias;
}
