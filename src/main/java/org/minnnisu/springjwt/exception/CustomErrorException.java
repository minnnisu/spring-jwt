package org.minnnisu.springjwt.exception;

import lombok.Getter;
import org.minnnisu.springjwt.constant.ErrorCode;

@Getter
public class CustomErrorException extends RuntimeException{
    private final ErrorCode errorCode;

    public CustomErrorException(ErrorCode errorCode){
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
