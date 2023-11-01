package com.alibou.security.auth;

import com.alibou.security.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
  private int id;
  private String firstname;
  private String lastname;
  private String email;
  private String password;
  private Role role;
  private Integer status;
  private Integer number;
  private String location;
  private Long ci;
  private Integer age;
  private Date init_date;
  private Date end_date;
}
