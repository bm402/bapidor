package com.github.bncrypted.bapidor.listener;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.github.bncrypted.bapidor.endpoint.EndpointStore;
import com.github.bncrypted.bapidor.model.EndpointDetails;
import com.github.bncrypted.bapidor.request.RequestParser;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Map;

public class HttpListener implements IHttpListener {
    private final IExtensionHelpers helpers;
    private final OutputStream stdout;
    private final OutputStream stderr;

    private final RequestParser requestParser;

    public HttpListener(IExtensionHelpers helpers,
                        OutputStream stdout,
                        OutputStream stderr) {

        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;

        this.requestParser = new RequestParser();
    }

    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {

        if (messageIsRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            URL requestUrl = requestInfo.getUrl();

            String method = requestInfo.getMethod();
            String path = requestUrl.getPath();
            Map<String, String> headers = requestParser.parseHeaders(requestInfo.getHeaders());
            Map<String, String> requestParams = requestParser.parseRequestParams(requestUrl.getQuery());
            Map<String, Object> bodyParams = requestParser.parseBodyParams(
                    messageInfo.getRequest(), requestInfo.getBodyOffset(), headers.get("Content-Type"));

            EndpointDetails endpointDetails = EndpointDetails.builder()
                    .method(method)
                    .path(path)
                    .headers(headers)
                    .requestParams(requestParams)
                    .bodyParams(bodyParams)
                    .build();

            String endpointCode = requestParser.getEndpointCode(method, path);
            EndpointStore.INSTANCE.addEndpointDetailsToStore(endpointCode, endpointDetails);

            PrintWriter logger = new PrintWriter(stdout, true);
            logger.println("Wrote to store: " + endpointCode);
        }
    }
}
