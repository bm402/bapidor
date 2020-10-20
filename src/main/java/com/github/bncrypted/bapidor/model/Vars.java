package com.github.bncrypted.bapidor.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Vars {
    private Object high;
    private Object low;
    private String alias;
}
