package com.github.bncrypted.bapidor.listener;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.PrintWriter;
import java.util.Arrays;

public class HttpListener implements IHttpListener {
    private final IBurpExtenderCallbacks callbacks;

    public HttpListener(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

        if (messageIsRequest) {
            StringBuilder logMessage = new StringBuilder();

            logMessage.append("HTTPService: ");
            logMessage.append(messageInfo.getHttpService());
            logMessage.append("\n");

            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);

            logMessage.append("Method: ");
            logMessage.append(requestInfo.getMethod());
            logMessage.append("\n");

            logMessage.append("Headers:\n");
            logMessage.append(requestInfo.getHeaders());
            logMessage.append("\n");

            logMessage.append("Parameters:\n");
            requestInfo.getParameters().stream()
                    .forEach(param -> {
                        logMessage.append(param.getType() + ": " + param.getName() + " " + param.getValue() + "\n");
                    });
            logMessage.append(requestInfo.getParameters().toString());
            logMessage.append("\n");

            int bodyOffset = requestInfo.getBodyOffset();
            byte[] request = messageInfo.getRequest();
            logMessage.append("Body:\n");
            logMessage.append(Arrays.copyOfRange(request, bodyOffset, request.length));
            logMessage.append("\n");

            stdout.println(logMessage.toString());
        }
    }
}
