package com.modernisc.security.keycloak.iam.util;


import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class BaseBusinessException extends RuntimeException {
    protected String code;
    protected HttpStatus httpStatusCode;
    protected String extraData;
    private Map<String, Object> messageArgs;
    private ApiError apiError;

    public BaseBusinessException() {
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    protected BaseBusinessException(Throwable cause) {
        super(cause);
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    public BaseBusinessException(String message) {
        super(message);
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    public BaseBusinessException(String message, Throwable cause) {
        super(message, cause);
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    public BaseBusinessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    public BaseBusinessException(List<BaseBusinessException> exceptions) {
        this.addMessageExceptions(exceptions);
        this.httpStatusCode = HttpStatus.BAD_REQUEST;
    }

    public Object getMessageArg(String key) {
        return (messageArgs==null ||messageArgs.isEmpty()) ? "" : this.messageArgs.get(key);
    }

    public void addMessageArg(String messageArg, Object messageVal) {
        if (messageArgs==null || messageArgs.isEmpty()) {
            this.messageArgs = new HashMap();
        }

        this.messageArgs.put(messageArg, messageVal);
    }

    public void addMessageExceptions(final List<BaseBusinessException> exceptions) {
        if (messageArgs==null ||messageArgs.isEmpty()) {
            this.messageArgs = new HashMap();
        }

        this.messageArgs.put("exceptions", exceptions);
    }

    public Map<String, Object> getMessageArgs() {
        return (messageArgs!=null  && !messageArgs.isEmpty()) ? this.messageArgs : null;
    }

    public abstract String getErrorCode();

    public HttpStatus getHttpStatus() {
        return this.httpStatusCode;
    }

    public String getExtraData() {
        return this.extraData;
    }

    public ApiError getApiError() {
        return this.apiError;
    }

    public void setApiError(ApiError apiError) {
        this.apiError = apiError;
    }
}