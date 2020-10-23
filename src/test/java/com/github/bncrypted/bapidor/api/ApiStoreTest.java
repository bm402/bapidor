package com.github.bncrypted.bapidor.api;

import com.github.bncrypted.bapidor.model.AuthDetails;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Privilege;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ApiStoreTest {
    private ApiStore apiStore;

    @BeforeEach
    void init() {
        apiStore = new ApiStore();
        apiStore.setBaseUri("https://test.com");
        apiStore.setAuthDetails(AuthDetails.builder()
                .headerName("Authorization")
                .headerValuePrefix("Bearer")
                .highPrivilegedToken("hi")
                .lowPrivilegedToken("lo")
                .build());
    }

    @Test
    void apistoretest1_whenSavingUnevaluatedEndpoint_thenShouldOnlyBeSavedInUnevaluatedFile() {
        EndpointDetails endpointDetails = EndpointDetails.builder()
                .method("GET")
                .path("/users")
                .headers(Map.of("Authorization", "Bearer hi"))
                .requestParams(Map.of())
                .bodyParams(Map.of())
                .privilege(Privilege.HIGH)
                .build();

        apiStore.addEndpointDetails("GET/users", endpointDetails);

        ClassLoader classLoader = ApiStore.class.getClassLoader();
        String evaluatedSaveFile = classLoader.getResource("apistoretest1/test.yml").getPath();
        apiStore.save(evaluatedSaveFile);

        assertTrue(areFilesEqual("apistoretest1/evaluated_expected.yml", "apistoretest1/test.yml"));
        assertTrue(areFilesEqual("apistoretest1/unevaluated_expected.yml", "apistoretest1/test.unevaluated.yml"));
    }

    @Test
    void apistoretest2_whenSavingEvaluatedEndpoint_thenShouldOnlyBeSavedInEvaluatedFile() {
        EndpointDetails endpointDetails1 = EndpointDetails.builder()
                .method("GET")
                .path("/users/123")
                .headers(Map.of("Authorization", "Bearer hi"))
                .requestParams(Map.of())
                .bodyParams(Map.of())
                .privilege(Privilege.HIGH)
                .isEvaluated(false)
                .build();

        EndpointDetails endpointDetails2 = EndpointDetails.builder()
                .method("GET")
                .path("/users/456")
                .headers(Map.of("Authorization", "Bearer lo"))
                .requestParams(Map.of())
                .bodyParams(Map.of())
                .privilege(Privilege.LOW)
                .build();

        apiStore.addEndpointDetails("GET/users/", endpointDetails1);
        apiStore.addEndpointDetails("GET/users/", endpointDetails2);

        ClassLoader classLoader = ApiStore.class.getClassLoader();
        String evaluatedSaveFile = classLoader.getResource("apistoretest2/test.yml").getPath();
        apiStore.save(evaluatedSaveFile);

        assertTrue(areFilesEqual("apistoretest2/evaluated_expected.yml", "apistoretest2/test.yml"));
        assertTrue(areFilesEqual("apistoretest2/unevaluated_expected.yml", "apistoretest2/test.unevaluated.yml"));
    }

    private boolean areFilesEqual(String file1, String file2) {
        ClassLoader classLoader = ApiStore.class.getClassLoader();
        try (InputStream inputStream1 = classLoader.getResourceAsStream(file1);
             InputStream inputStream2 = classLoader.getResourceAsStream(file2)) {

            BufferedReader reader1 = new BufferedReader(new InputStreamReader(inputStream1));
            BufferedReader reader2 = new BufferedReader(new InputStreamReader(inputStream2));

            while (reader1.ready() && reader2.ready()) {
                String line1 = reader1.readLine();
                String line2 = reader2.readLine();
                if (!line1.equals(line2)) {
                    return false;
                }
            }

            if (reader1.ready() || reader2.ready()) {
                return false;
            }

        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        return true;
    }
}
