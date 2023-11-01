package com.alibou.security.user;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserResponse {
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String password;
    private Integer status;
    private Integer number;
    private String location;
    private Integer ci;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Role role;
}
