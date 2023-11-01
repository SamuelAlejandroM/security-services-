package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import com.alibou.security.exceptions.BadRequestException;
import com.alibou.security.token.Token;
import com.alibou.security.token.TokenRepository;
import com.alibou.security.token.TokenType;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Optional.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;
  @Autowired
  JdbcTemplate jdbcTemplate;
  protected final Log logger = LogFactory.getLog(this.getClass());

  public AuthenticationResponse register(RegisterRequest request) {
    if (repository.existsByEmail(request.getEmail())) {
      throw new BadRequestException("Sorry, this email is already taken. Please choose a different one.");
    }
              var user = User.builder()
              .firstname(request.getFirstname())
              .lastname(request.getLastname())
              .email(request.getEmail())
              .password(passwordEncoder.encode(request.getPassword()))
              .role(request.getRole())
              .status(1)
              .ci(Math.toIntExact(request.getCi()))
              .age(request.getAge())
              .number(request.getNumber())
              .location(request.getLocation())
              .init_date(request.getInit_date())
              .end_date(request.getEnd_date())
              .build();
      var savedUser = repository.save(user);
      var jwtToken = jwtService.generateToken(user);
      var refreshToken = jwtService.generateRefreshToken(user);
      saveUserToken(savedUser, jwtToken);
      return AuthenticationResponse.builder()
              .accessToken(jwtToken)
              .refreshToken(refreshToken)
              .build();

  }
  public List<AuthenticationResponse> insertCustomer(RegisterRequest request) {

    if (repository.existsByEmail(request.getEmail())) {
     throw new BadRequestException("Sorry, this email is already taken. Please choose a different one.");

    }
    final StringBuilder sql = new StringBuilder();
    sql.append("INSERT INTO _user(\n" +
            "ci, email, firstname, lastname, location, \"number\", password, role, status)\n" +
            "VALUES \n" +
            "    (?, ?, ?, ?, ?, ?, ?, ?, ?);\n");
    logger.debug("Executing:" + sql + " ; param: " + request);
    GeneratedKeyHolder holder = new GeneratedKeyHolder();
    jdbcTemplate.update( new PreparedStatementCreator() {
      @Override
      public PreparedStatement createPreparedStatement(Connection connection) throws SQLException {
        PreparedStatement ps = connection.prepareStatement(sql.toString(), Statement.RETURN_GENERATED_KEYS);
        ps.setLong(1,request.getCi());
        ps.setString(2, request.getEmail());
        ps.setString(3, request.getFirstname());
        ps.setString(4, request.getLastname());
        ps.setString(5, request.getLocation());
        ps.setInt(6, request.getNumber());
        ps.setString(7, passwordEncoder.encode(request.getPassword()));
        ps.setString(8, "USER");
        ps.setInt(9, 1);
        return ps;
      }
    }, holder);
    logger.debug("Executing:" + holder + " ; param: " + request);
    var user = repository.findByEmail(request.getEmail())
            .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    saveUserToken(user, jwtToken);
    AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
            .accessToken(jwtToken)
            .refreshToken(refreshToken)
            .build();
    List<AuthenticationResponse> authenticationResponseList = new ArrayList<>();
    authenticationResponseList.add(authenticationResponse);
    return authenticationResponseList;
  }
  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    revokeAllUserTokens(user);
    saveUserToken(user, jwtToken);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();
    tokenRepository.save(token);
  }

  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
    if (validUserTokens.isEmpty())
      return;
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  public void refreshToken(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail)
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
}
