package com.modernisc.security.keycloak.iam.util;

import org.springframework.http.HttpStatus;

public class KeycloakException extends BaseBusinessException {
    public KeycloakException() {
        super();

    }
    public KeycloakException(HttpStatus httpStatusCode){
        super();
        this.httpStatusCode = httpStatusCode;
    }
    public KeycloakException(ApiError apiError){
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