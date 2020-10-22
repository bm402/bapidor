package com.github.bncrypted.bapidor.listener;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.github.bncrypted.bapidor.api.ApiStore;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.model.Privilege;
import com.github.bncrypted.bapidor.request.RequestParser;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Map;

public class HttpListener implements IHttpListener {

    private final ApiStore apiStore;
    private final IExtensionHelpers helpers;
    private final OutputStream stdout;
    private final RequestParser requestParser;

    public HttpListener(ApiStore apiStore,
                        IExtensionHelpers helpers,
                        OutputStream stdout) {

        this.apiStore = apiStore;
        this.helpers = helpers;
        this.stdout = stdout;
        this.requestParser = new RequestParser(apiStore);
    }

    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {

        if (apiStore.isListening() && messageIsRequest) {
            PrintWriter logger = new PrintWriter(stdout, true);
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL requestUrl = requestInfo.getUrl();

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

            String endpointCode = requestParser.getEndpointCode(method, path);
            apiStore.addEndpointDetails(endpointCode, endpointDetails);
            logger.println("Wrote to store: " + requestInfo.getHeaders().get(0));
        }
    }
}
