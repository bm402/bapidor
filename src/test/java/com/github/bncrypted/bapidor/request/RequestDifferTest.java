package com.github.bncrypted.bapidor.request;

import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.AuthDetails;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RequestDifferTest {

    private static ApiStore apiStore;
    private RequestDiffer requestDiffer;

    @BeforeAll
    static void init() {
        apiStore = new ApiStore();
    }

    @BeforeEach
    void initEach() {
        requestDiffer = new RequestDiffer(apiStore);
    }

    @Test
    void whenHeadersContainAuthHeaders_thenShouldAllBeRemoved() {
        apiStore.setAuthDetails(AuthDetails.builder()
                .headerName("X-Custom-Auth")
                .build());

        Map<String, String> headers = Map.of(
            "X-SomeId", "id",
            "Authorization", "Bearer token",
            "Cookie", "Some cookie",
            "X-Custom-Auth", "Custom auth"
        );

        Map<String, String> expectedHeaders = Map.of("X-SomeId", "id");
        Map<String, String> actualHeaders = requestDiffer.sanitiseHighPrivilegedHeaders(headers);

        assertEquals(expectedHeaders, actualHeaders);
    }

    @Test
    void whenPathsAreSame_thenNoVarsShouldBeAdded() {
        String highPrivilegedPath = "/users/me";
        String lowPrivilegedPath = "/users/me";

        String expectedPathWithIndicators = "/users/me";
        String actualPathWithIndicators = requestDiffer.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);
        int expectedVarsInStore = 0;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedPathWithIndicators, actualPathWithIndicators);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenPathsHaveOneVariable_thenVarShouldBeAdded() {
        String highPrivilegedPath = "/users/1028";
        String lowPrivilegedPath = "/users/4927";

        String pathWithIndicators = requestDiffer.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);
        int expectedVarsInPath = 1;
        int actualVarsInPath = countVarsInPath(pathWithIndicators);
        int expectedVarsInStore = 1;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedVarsInPath, actualVarsInPath);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenPathsHaveMoreThanOneVariable_thenAllVarsShouldBeAdded() {
        String highPrivilegedPath = "/org/aws/users/1028";
        String lowPrivilegedPath = "/org/azure/users/4927";

        String pathWithIndicators = requestDiffer.createPathWithVarIds(highPrivilegedPath, lowPrivilegedPath);
        int expectedVarsInPath = 2;
        int actualVarsInPath = countVarsInPath(pathWithIndicators);
        int expectedVarsInStore = 2;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedVarsInPath, actualVarsInPath);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenRequestParamsHaveNoVariables_thenNoVarsShouldBeAdded() {
        Map<String, String> highPrivilegedRequestParams = Map.of("p1", "p1", "p2", "p2");
        Map<String, String> lowPrivilegedRequestParams = Map.of("p1", "p1", "p2", "p2");

        Map<String, String> expectedRequestParams = Map.of("p1", "p1", "p2", "p2");
        Map<String, String> actualRequestParams = requestDiffer.createRequestParamsWithVarIds(
                highPrivilegedRequestParams, lowPrivilegedRequestParams);
        int expectedVarsInStore = 0;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedRequestParams, actualRequestParams);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenRequestParamsAreDifferentAndHaveNoVariables_thenCommonParamsShouldBeIncludedAndNoVarsShouldBeAdded() {
        Map<String, String> highPrivilegedRequestParams = Map.of("p1", "p1", "p2", "p2");
        Map<String, String> lowPrivilegedRequestParams = Map.of("p2", "p2", "p3", "p3");

        Map<String, String> expectedRequestParams = Map.of("p2", "p2");
        Map<String, String> actualRequestParams = requestDiffer.createRequestParamsWithVarIds(
                highPrivilegedRequestParams, lowPrivilegedRequestParams);
        int expectedVarsInStore = 0;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedRequestParams, actualRequestParams);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenRequestParamsHaveOneVariable_thenVarShouldBeAdded() {
        Map<String, String> highPrivilegedRequestParams = Map.of("org", "aws");
        Map<String, String> lowPrivilegedRequestParams = Map.of("org", "azure");

        Map<String, String> actualRequestParams = requestDiffer.createRequestParamsWithVarIds(
                highPrivilegedRequestParams, lowPrivilegedRequestParams);
        int expectedVarsInStore = 1;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals("$var", actualRequestParams.get("org").substring(0, 4));
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenRequestParamsHaveMoreThanOneVariable_thenAllVarsShouldBeAdded() {
        Map<String, String> highPrivilegedRequestParams = Map.of("org", "aws", "user", "bncrypted", "action", "get");
        Map<String, String> lowPrivilegedRequestParams = Map.of("org", "azure", "user", "bob", "action", "get");

        Map<String, String> actualRequestParams = requestDiffer.createRequestParamsWithVarIds(
                highPrivilegedRequestParams, lowPrivilegedRequestParams);
        int expectedVarsInStore = 2;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals("$var", actualRequestParams.get("org").substring(0, 4));
        assertEquals("$var", actualRequestParams.get("user").substring(0, 4));
        assertEquals("get", actualRequestParams.get("action"));
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenBodyParamsHaveNoVariables_thenNoVarsShouldBeAdded() {
        Map<String, Object> highPrivilegedBodyParams = Map.of(
                "action", "get",
                "list", List.of("p1", "p2"),
                "map", Map.of("p3", "p3", "p4", "p4")
        );
        Map<String, Object> lowPrivilegedBodyParams = Map.of(
                "action", "get",
                "list", List.of("p1", "p2"),
                "map", Map.of("p3", "p3", "p4", "p4")
        );

        Map<String, Object> expectedBodyParams = Map.of(
                "action", "get",
                "list", List.of("p1", "p2"),
                "map", Map.of("p3", "p3", "p4", "p4")
        );
        Map<String, Object> actualBodyParams = requestDiffer.createBodyParamsWithVarIds(
                highPrivilegedBodyParams, lowPrivilegedBodyParams);
        int expectedVarsInStore = 0;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals(expectedBodyParams, actualBodyParams);
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenBodyParamsHaveOneVariable_thenVarShouldBeAdded() {
        Map<String, Object> highPrivilegedBodyParams = Map.of("user", "bncrypted");
        Map<String, Object> lowPrivilegedBodyParams = Map.of("user", "bob");

        Map<String, Object> actualBodyParams = requestDiffer.createBodyParamsWithVarIds(
                highPrivilegedBodyParams, lowPrivilegedBodyParams);
        int expectedVarsInStore = 1;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals("$var", actualBodyParams.get("user").toString().substring(0, 4));
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenBodyParamsHaveMoreThanOneVariable_thenAllVarsShouldBeAdded() {
        Map<String, Object> highPrivilegedBodyParams = Map.of("user", "bncrypted", "id", 1);
        Map<String, Object> lowPrivilegedBodyParams = Map.of("user", "bob", "id", 2);

        Map<String, Object> actualBodyParams = requestDiffer.createBodyParamsWithVarIds(
                highPrivilegedBodyParams, lowPrivilegedBodyParams);
        int expectedVarsInStore = 2;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals("$var", actualBodyParams.get("user").toString().substring(0, 4));
        assertEquals("$var", actualBodyParams.get("id").toString().substring(0, 4));
        assertEquals(expectedVarsInStore, actualVarsInStore);
    }

    @Test
    void whenBodyParamsContainNestedVariables_thenAllVarsShouldBeAdded() {
        Map<String, Object> highPrivilegedListMap = Map.of("user", "bncrypted");
        List<Map<String, Object>> highPrivilegedList = List.of(highPrivilegedListMap);
        List<Integer> highPrivilegedMapList1 = List.of(123, 456);
        List<String> highPrivilegedMapList2 = List.of("get", "save");
        Map<String, Object> highPrivilegedMap = Map.of("list1", highPrivilegedMapList1, "list2", highPrivilegedMapList2);

        Map<String, Object> highPrivilegedBodyParams = Map.of(
                "id", 1,
                "action", "delete",
                "list", highPrivilegedList,
                "map", highPrivilegedMap
        );

        Map<String, Object> lowPrivilegedListMap = Map.of("user", "bob");
        List<Map<String, Object>> lowPrivilegedList = List.of(lowPrivilegedListMap);
        List<Integer> lowPrivilegedMapList1 = List.of(456, 456);
        List<String> lowPrivilegedMapList2 = List.of("delete", "save");
        Map<String, Object> lowPrivilegedMap = Map.of("list1", lowPrivilegedMapList1, "list2", lowPrivilegedMapList2);

        Map<String, Object> lowPrivilegedBodyParams = Map.of(
                "id", 2,
                "action", "get",
                "list", lowPrivilegedList,
                "map", lowPrivilegedMap
        );

        Map<String, Object> actualBodyParams = requestDiffer.createBodyParamsWithVarIds(
                highPrivilegedBodyParams, lowPrivilegedBodyParams);
        int expectedVarsInStore = 5;
        int actualVarsInStore = requestDiffer.getVars().size();

        assertEquals("$var", actualBodyParams.get("id").toString().substring(0, 4));
        assertEquals("$var", actualBodyParams.get("action").toString().substring(0, 4));
        assertEquals("$var", ((Map)((List)actualBodyParams.get("list")).get(0)).get("user").toString().substring(0, 4));
        assertEquals("$var", ((List)((Map)actualBodyParams.get("map")).get("list1")).get(0).toString().substring(0, 4));
        assertEquals(456, ((List)((Map)actualBodyParams.get("map")).get("list1")).get(1));
        assertEquals("$var", ((List)((Map)actualBodyParams.get("map")).get("list2")).get(0).toString().substring(0, 4));
        assertEquals("save", ((List)((Map)actualBodyParams.get("map")).get("list2")).get(1));
        assertEquals(expectedVarsInStore, actualVarsInStore);
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
