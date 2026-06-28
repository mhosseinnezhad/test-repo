package com.modernisc.security.keycloak.iam.util;

import org.springframework.http.HttpStatus;

public class UnauthenticatedException extends BaseBusinessException {
    public UnauthenticatedException() {
        super();
        code = "misc.exceptions.security.3003";
    }
    public UnauthenticatedException(HttpStatus httpStatusCode){
        this();
        this.httpStatusCode = httpStatusCode;
    }
    public UnauthenticatedException(ApiError apiError){
        super();
        httpStatusCode = apiError.getStatus();
        code = apiError.getCode();
        extraData = apiError.getExtraData();
        addMessageArg(apiError.getLocalizedMessage(), apiError);
        this.setApiError( apiError );
    }

    @Override
    public String getErrorCode() {
        return code;
    }

}