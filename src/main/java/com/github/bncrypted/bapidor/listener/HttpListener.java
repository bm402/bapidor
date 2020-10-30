package com.github.bncrypted.bapidor.listener;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Privilege;
import com.github.bncrypted.bapidor.request.RequestParser;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpListener implements IHttpListener {

    private final Map<String, ApiStore> apiStores;
    private final IExtensionHelpers helpers;
    private final OutputStream stdout;
    private final Map<String, RequestParser> requestParsers;

    public HttpListener(Map<String, ApiStore> apiStores,
                        IExtensionHelpers helpers,
                        OutputStream stdout) {

        this.apiStores = apiStores;
        this.helpers = helpers;
        this.stdout = stdout;
        this.requestParsers = new HashMap<>();
    }

    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {

        if (!messageIsRequest) {
            return;
        }

        String baseUri = getBaseUri(messageInfo.getHttpService());
        ApiStore apiStore = apiStores.get(baseUri);

        if (apiStore != null && apiStore.isListening()) {

            RequestParser requestParser = requestParsers.get(baseUri);
            if (requestParser == null) {
                requestParser = new RequestParser(apiStore);
                requestParsers.put(baseUri, requestParser);
            }

            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL requestUrl = requestInfo.getUrl();

            PrintWriter logger = new PrintWriter(stdout, true);
            logger.println("Incoming request: " + requestInfo.getHeaders().get(0));

            String method = requestInfo.getMethod();
            String path = requestUrl.getPath();
            Map<String, String> headers = requestParser.parseHeaders(requestInfo.getHeaders());
            Map<String, String> requestParams = requestParser.parseRequestParams(requestUrl.getQuery());
            Map<String, Object> bodyParams = requestParser.parseBodyParams(
                    messageInfo.getRequest(), requestInfo.getBodyOffset(), headers.get("Content-Type"));

            Privilege privilege = requestParser.findPrivilege(
                    headers.get(apiStore.getAuthDetails().getHeaderName()));
            if (privilege == Privilege.NONE) {
                logger.println("[Skipping] No token found for: " + requestInfo.getHeaders().get(0));
                return;
            }

            EndpointDetails endpointDetails = EndpointDetails.builder()
                    .method(method)
                    .path(path)
                    .headers(headers)
                    .requestParams(requestParams)
                    .bodyParams(bodyParams)
                    .privilege(privilege)
                    .build();

            List<IParameter> allParams = requestInfo.getParameters();
            String endpointCode = requestParser.getEndpointCode(method, path, allParams);

            apiStore.addEndpointDetails(endpointCode, endpointDetails);
            logger.println("Wrote to store: " + requestInfo.getHeaders().get(0));
        }
    }

    private String getBaseUri(IHttpService httpService) {
        StringBuilder baseUri = new StringBuilder();
        baseUri.append(httpService.getProtocol());
        baseUri.append("://");
        baseUri.append(httpService.getHost());
        int port = httpService.getPort();
        if (port != 0 && port != 80 && port != 443) {
            baseUri.append(":");
            baseUri.append(port);
        }
        return baseUri.toString();
    }
}
