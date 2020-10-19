package com.github.bncrypted.bapidor.request;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;

public class RequestParserTest {
    private final RequestParser requestParser = new RequestParser();

    @Test
    void whenEndpointContainsNoUUIDsOrIntegers_thenNothingShouldBeRemoved() {
        String topLineOfHeader = "GET /user/me";

        String expectedEndpointCode = "GET/user/me";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsUUID_thenItShouldBeRemoved() {
        String topLineOfHeader = "GET /user/" + UUID.randomUUID().toString();

        String expectedEndpointCode = "GET/user/";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsMoreThanOneUUID_thenAllUUIDsShouldBeRemoved() {
        String topLineOfHeader = "POST /org/" + UUID.randomUUID().toString() +
                "/user/" + UUID.randomUUID().toString() + "/delete";

        String expectedEndpointCode = "POST/org//user//delete";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsInteger_thenItShouldBeRemoved() {
        String topLineOfHeader = "GET /user/1";

        String expectedEndpointCode = "GET/user/";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsMoreThanOneInteger_thenAllIntegersShouldBeRemoved() {
        String topLineOfHeader = "POST /org/12/user/425/delete";

        String expectedEndpointCode = "POST/org//user//delete";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }

    @Test
    void whenEndpointContainsBothUUIDAndInteger_thenBothShouldBeRemoved() {
        String topLineOfHeader = "GET /org/52/user/" + UUID.randomUUID().toString() ;

        String expectedEndpointCode = "GET/org//user/";
        String actualEndpointCode = requestParser.getEndpointCode(topLineOfHeader);

        assertEquals(expectedEndpointCode, actualEndpointCode);
    }
}
