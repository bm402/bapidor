package com.github.bncrypted.bapidor.request;

import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.Vars;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
public class RequestDiffer {

    private final Map<String, Vars> vars;

    public RequestDiffer() {
        vars = new HashMap<>();
    }

    public String createPathWithVarIds(String highPrivilegedPath, String lowPrivilegedPath) {
        String[] highPrivilegedPathComponents = highPrivilegedPath.split("/");
        String[] lowPrivilegedPathComponents = lowPrivilegedPath.split("/");
        StringBuilder pathWithVarsIds = new StringBuilder();

        for (int i = 1; i < highPrivilegedPathComponents.length; i++) {
            if (highPrivilegedPathComponents[i].equals(lowPrivilegedPathComponents[i])) {
                pathWithVarsIds.append("/");
                pathWithVarsIds.append(highPrivilegedPathComponents[i]);
            } else {
                String varId = ApiStore.INSTANCE.getNextVarId();
                Vars varDetails = Vars.builder()
                        .high(highPrivilegedPathComponents[i])
                        .low(lowPrivilegedPathComponents[i])
                        .build();
                vars.put(varId, varDetails);
                pathWithVarsIds.append("/$");
                pathWithVarsIds.append(varId);
            }
        }

        return pathWithVarsIds.toString();
    }
}
