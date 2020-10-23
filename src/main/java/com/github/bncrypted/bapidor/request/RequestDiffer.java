package com.github.bncrypted.bapidor.request;

import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.Vars;
import lombok.Getter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class RequestDiffer {

    private final ApiStore apiStore;
    private final Map<String, Vars> vars;

    public RequestDiffer(ApiStore apiStore) {
        this.apiStore = apiStore;
        vars = new HashMap<>();
    }

    public Map<String, String> sanitiseHighPrivilegedHeaders(Map<String, String> highPrivilegedHeaders) {
        Map<String, String> headers = new HashMap<>(highPrivilegedHeaders);
        headers.remove("Authorization");
        headers.remove("Cookie");
        headers.remove(apiStore.getAuthDetails().getHeaderName());
        return headers;
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
                String varId = createVar(highPrivilegedPathComponents[i], lowPrivilegedPathComponents[i]);
                pathWithVarsIds.append("/$");
                pathWithVarsIds.append(varId);
            }
        }

        return pathWithVarsIds.toString();
    }

    public Map<String, String> createRequestParamsWithVarIds(Map<String, String> highPrivilegedRequestParams,
                                                             Map<String, String> lowPrivilegedRequestParams) {

        Map<String, String> requestParamsWithVarIds = new HashMap<>();
        highPrivilegedRequestParams.forEach((paramName, highPrivilegedParamValue) -> {
            if (lowPrivilegedRequestParams.containsKey(paramName)) {
                if (highPrivilegedParamValue.equals(lowPrivilegedRequestParams.get(paramName))) {
                    requestParamsWithVarIds.put(paramName, highPrivilegedParamValue);
                } else {
                    String varId = createVar(highPrivilegedParamValue,
                            lowPrivilegedRequestParams.get(paramName), paramName);
                    requestParamsWithVarIds.put(paramName, "$"+varId);
                }
            }
        });

        return requestParamsWithVarIds;
    }

    public Map<String, Object> createBodyParamsWithVarIds(Map<String, Object> highPrivilegedBodyParams,
                                                          Map<String, Object> lowPrivilegedBodyParams) {

        return createMapWithVarIds(highPrivilegedBodyParams, lowPrivilegedBodyParams);
    }

    private Class<?> findCollectionType(Object a, Object b) {
        if (a instanceof Map && b instanceof Map) {
            return Map.class;
        }
        if (a instanceof List && b instanceof List) {
            return List.class;
        }
        return Object.class;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> createMapWithVarIds(Map<String, Object> highPrivilegedMap,
                                                    Map<String, Object> lowPrivilegedMap) {

        Map<String, Object> mapWithVarIds = new HashMap<>();
        highPrivilegedMap.forEach((key, highPrivilegedValue) -> {
            if (lowPrivilegedMap.containsKey(key)) {
                Object lowPrivilegedValue = lowPrivilegedMap.get(key);
                Class<?> objectClass = findCollectionType(highPrivilegedValue, lowPrivilegedValue);
                if (objectClass.equals(Map.class)) {
                    mapWithVarIds.put(key, createMapWithVarIds((Map<String, Object>)highPrivilegedValue,
                            (Map<String, Object>)lowPrivilegedValue));
                } else if (objectClass.equals(List.class)) {
                    mapWithVarIds.put(key, createListWithVarIds((List<Object>)highPrivilegedValue,
                            (List<Object>)lowPrivilegedValue));
                } else {
                    if (highPrivilegedValue.equals(lowPrivilegedValue)) {
                        mapWithVarIds.put(key, highPrivilegedValue);
                    } else {
                        String varId = createVar(highPrivilegedValue, lowPrivilegedValue, key);
                        mapWithVarIds.put(key, "$"+varId);
                    }
                }
            }
        });

        return mapWithVarIds;
    }

    @SuppressWarnings("unchecked")
    private List<Object> createListWithVarIds(List<Object> highPrivilegedList, List<Object> lowPrivilegedList) {
        List<Object> listWithVarIds = new ArrayList<>();
        for (int i = 0; i < highPrivilegedList.size(); i++) {
            if (i < lowPrivilegedList.size()) {
                Object highPrivilegedValue = highPrivilegedList.get(i);
                Object lowPrivilegedValue = lowPrivilegedList.get(i);
                Class<?> objectClass = findCollectionType(highPrivilegedValue, lowPrivilegedValue);
                if (objectClass.equals(Map.class)) {
                    listWithVarIds.add(createMapWithVarIds((Map<String, Object>)highPrivilegedValue,
                            (Map<String, Object>)lowPrivilegedValue));
                } else if (objectClass.equals(List.class)) {
                    listWithVarIds.add(createListWithVarIds((List<Object>)highPrivilegedValue,
                                (List<Object>)lowPrivilegedValue));
                } else {
                    if (highPrivilegedValue.equals(lowPrivilegedValue)) {
                        listWithVarIds.add(highPrivilegedValue);
                    } else {
                        String varId = createVar(highPrivilegedValue, lowPrivilegedValue);
                        listWithVarIds.add("$"+varId);
                    }
                }
            } else {
                break;
            }
        }

        return listWithVarIds;
    }

    private String createVar(Object highPrivilegedValue, Object lowPrivilegedValue) {
        return createVar(highPrivilegedValue, lowPrivilegedValue, null);
    }

    private String createVar(Object highPrivilegedValue, Object lowPrivilegedValue, String alias) {
        String varId = apiStore.getNextVarId();
        Vars varDetails = Vars.builder()
                .high(highPrivilegedValue)
                .low(lowPrivilegedValue)
                .alias(alias)
                .build();
        vars.put(varId, varDetails);
        return varId;
    }
}
