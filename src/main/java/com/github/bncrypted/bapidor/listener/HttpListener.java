package com.github.bncrypted.bapidor.listener;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Arrays;

public class HttpListener implements IHttpListener {
    private final IExtensionHelpers helpers;
    private final OutputStream stdout;
    private final OutputStream stderr;

    public HttpListener(IExtensionHelpers helpers,
                        OutputStream stdout,
                        OutputStream stderr) {

        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public void processHttpMessage(int toolFlag,
                                   boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {

        PrintWriter logger = new PrintWriter(stdout, true);

        if (messageIsRequest) {
            StringBuilder logMessage = new StringBuilder();

            logMessage.append("HTTPService: ");
            logMessage.append(messageInfo.getHttpService());
            logMessage.append("\n");

            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

            logMessage.append("Method: ");
            logMessage.append(requestInfo.getMethod());
            logMessage.append("\n");

            logMessage.append("Headers:\n");
            logMessage.append(requestInfo.getHeaders());
            logMessage.append("\n");

            logMessage.append("Parameters:\n");
            requestInfo.getParameters().forEach(param ->
                    logMessage.append(param.getType() + ": " + param.getName() + " " + param.getValue() + "\n"));
            logMessage.append("\n");

            int bodyOffset = requestInfo.getBodyOffset();
            byte[] request = messageInfo.getRequest();
            byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
            logMessage.append("Body:\n");
            logMessage.append(new String(body));
            logMessage.append("\n");

            logger.println(logMessage.toString());
        }
    }
}
