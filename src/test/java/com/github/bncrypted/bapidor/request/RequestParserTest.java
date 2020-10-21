package com.github.bncrypted.bapidor.request;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

public class RequestParserTest {
    private final RequestParser requestParser = new RequestParser();

    @Test
    void whenEndpointContainsNoUUIDsOrIntegers_thenNothingShouldBeRemoved() {
        String method = "GET";
        String path = "/user/me";

        String expectedEndpointCode = "GET/user/me";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsUUID_thenItShouldBeRemoved() {
        String method = "GET";
        String path = "/user/" + UUID.randomUUID().toString();

        String expectedEndpointCode = "GET/user/";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsMoreThanOneUUID_thenAllUUIDsShouldBeRemoved() {
        String method = "POST";
        String path = "/org/" + UUID.randomUUID().toString() +
                "/user/" + UUID.randomUUID().toString() + "/delete";

        String expectedEndpointCode = "POST/org//user//delete";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsInteger_thenItShouldBeRemoved() {
        String method = "GET";
        String path = "/user/1";

        String expectedEndpointCode = "GET/user/";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsMoreThanOneInteger_thenAllIntegersShouldBeRemoved() {
        String method = "POST";
        String path = "/org/12/user/425/delete";

        String expectedEndpointCode = "POST/org//user//delete";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsBothUUIDAndInteger_thenBothShouldBeRemoved() {
        String method = "GET";
        String path = "/org/52/user/" + UUID.randomUUID().toString();

        String expectedEndpointCode = "GET/org//user/";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsUsername_thenShouldBeRemoved() {
        String method = "PATCH";
        String path = "/user/bncrypted/delete";

        String expectedEndpointCode = "PATCH/user//delete";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsFilename_thenShouldNotBeRemoved() {
        String method = "PUT";
        String path = "/file/bncrypted.json/delete";

        String expectedEndpointCode = "PUT/file/bncrypted.json/delete";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsObjectWithDashSeparator_thenShouldNotBeRemoved() {
        String method = "GET";
        String path = "/component-v1/info";

        String expectedEndpointCode = "GET/component-v1/info";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsObjectWithUnderscoreSeparator_thenShouldNotBeRemoved() {
        String method = "GET";
        String path = "/component_v1/info";

        String expectedEndpointCode = "GET/component_v1/info";
        String actualEndpointCode = requestParser.getEndpointCode(method, path);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }
}
