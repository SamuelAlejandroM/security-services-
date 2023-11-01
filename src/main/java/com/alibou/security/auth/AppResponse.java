package com.alibou.security.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;


    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class AppResponse {
        public String responseCode;
        public String responseMessage;
        public Object data;

        public AppResponse() {
            responseCode = "OK";
            responseMessage = "OK";
        }



}
