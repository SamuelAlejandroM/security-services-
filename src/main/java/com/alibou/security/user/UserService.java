package com.alibou.security.user;

import com.alibou.security.auth.RegisterRequest;
import com.alibou.security.exceptions.BadRequestException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService{

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    @Autowired
    JdbcTemplate jdbcTemplate;
    protected final Log logger = LogFactory.getLog(this.getClass());
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        // check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }

        // update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // save the new password
        repository.save(user);
    }

    public void updateCustomer(RegisterRequest request) {
        final StringBuilder sql = new StringBuilder();
        sql.append("UPDATE _user\n" +
                "\tSET ci=?," +
                "\temail=?, " +
                "\tfirstname=?, " +
                "\tlastname=?, " +
                "\tlocation=?, " +
                "\"number\"=?, " +
                "\trole=?, " +
                "\tstatus=?\n" +
                "\tWHERE id=?;"
        );
        logger.debug("Executing:" + sql + " ; param: " + request);
        jdbcTemplate.update(sql.toString(), new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setLong(1,request.getCi());
                ps.setString(2, request.getEmail());
                ps.setString(3, request.getFirstname());
                ps.setString(4, request.getLastname());
                ps.setString(5, request.getLocation());
                ps.setInt(6, request.getNumber());
                ps.setString(7, "USER");
                ps.setInt(8, request.getStatus());
                ps.setInt(9, request.getId());
            }
        });
    }

    public void updateStatus(RegisterRequest request) {
        final StringBuilder sql = new StringBuilder();
        sql.append("UPDATE _user\n " +
                "\tSET status=?\n" +
                "\tWHERE id=?;"
        );
        logger.debug("Executing:" + sql + " ; param: " + request);
        jdbcTemplate.update(sql.toString(), new PreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setInt(1, request.getStatus());
                ps.setInt(2, request.getId());
            }
        });
    }

    public List<UserResponse> getCustomerData(){
        String sql ="SELECT id,ci, firstname, lastname, location, status, number,email FROM _user";
        logger.debug("Executing: " + sql);
        try {
            List<UserResponse> res = this.jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(UserResponse.class));
            logger.debug("Out: " + res);
            return res;
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }
    public List<UserResponse> getUserData(){
        String sql ="SELECT id,ci, firstname, lastname, location, status, number,email,role FROM _user";
        logger.debug("Executing: " + sql);
        try {
            List<UserResponse> res = this.jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(UserResponse.class));
            logger.debug("Out: " + res);
            return res;
        } catch (EmptyResultDataAccessException e) {
            return null;
        }
    }
}
