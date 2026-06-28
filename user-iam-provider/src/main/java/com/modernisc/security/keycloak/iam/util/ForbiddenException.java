package com.modernisc.security.keycloak.iam.util;

import org.springframework.http.HttpStatus;

public class ForbiddenException extends BaseBusinessException {
    public ForbiddenException() {
        super();
        code = "misc.exceptions.security.3004";
    }
    public ForbiddenException(HttpStatus httpStatusCode){
        this();
        this.httpStatusCode = httpStatusCode;
    }
    public ForbiddenException(ApiError apiError){
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