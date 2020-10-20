package com.github.bncrypted.bapidor.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthDetails {
    private final String headerName;
    private final String headerValuePrefix;
    private final String highPrivilegedToken;
    private final String lowPrivilegedToken;
}
