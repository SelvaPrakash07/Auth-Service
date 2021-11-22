package com.coherent.unnamed.auth.exception;/*
 *
 * Copyright (c) 2019 Coherent Limited
 *
 * All information contained herein is, and remains the property of Coherent
 * Limited. The intellectual and technical concepts contained herein are
 * proprietary to Coherent and are protected by logic secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from Coherent
 * Limited
 *
 */

public enum ErrorCode implements ErrorHandle {

    CAP_1002("1002", "User not found exception"),
    CAP_1005("1002", "Invalid grant type"),
    CAP_1003("1003", "User has been temporaly locked for continus five wrong attempt"),
    CAP_1004("1004", "Invalid Email"),
    CAP_1018("1018", "Invalid Input");

    private final String errorCode;
    private final String message;

    ErrorCode(String errorCode, String message) {
        this.errorCode = errorCode;
        this.message = message;
    }

    @Override
    public String getErrorCode() {
        return this.errorCode;
    }

    @Override
    public String getMessage() {
        return this.message;
    }

}