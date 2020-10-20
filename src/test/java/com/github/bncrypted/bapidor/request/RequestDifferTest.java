package com.github.bncrypted.bapidor.request;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RequestDifferTest {
    private final RequestDiffer rd = new RequestDiffer();

    @Test
    void whenPathsAreSame_thenNoVarsShouldBeAdded() {
        String highPrivilegedPath = "/users/me";
        String lowPrivilegedPath = "/users/me";

        String expectedPathWithIndicators = "/users/me";
        String actualPathWithIndicators = rd.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);

        assertEquals(expectedPathWithIndicators, actualPathWithIndicators);
    }

    @Test
    void whenPathsHaveOneVariable_thenVarShouldBeAdded() {
        String highPrivilegedPath = "/users/1028";
        String lowPrivilegedPath = "/users/4927";

        String pathWithIndicators = rd.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);
        int expectedVarsInPath = 1;
        int actualVarsInPath = countVarsInPath(pathWithIndicators);

        assertEquals(expectedVarsInPath, actualVarsInPath);
    }

    @Test
    void whenPathsHaveMoreThanOneVariable_thenAllVarsShouldBeAdded() {
        String highPrivilegedPath = "/org/aws/users/1028";
        String lowPrivilegedPath = "/org/azure/users/4927";

        String pathWithIndicators = rd.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);
        int expectedVarsInPath = 2;
        int actualVarsInPath = countVarsInPath(pathWithIndicators);

        assertEquals(expectedVarsInPath, actualVarsInPath);
    }

    private int countVarsInPath(String path) {
        int index = -1;
        int count = -1;
        do {
            count++;
            index = path.indexOf("var", index+1);
        } while (index != -1);
        return count;
    }
}
