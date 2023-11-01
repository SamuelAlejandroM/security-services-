package com.alibou.security.user;

import com.alibou.security.auth.AppResponse;
import com.alibou.security.auth.RegisterRequest;
import com.alibou.security.exceptions.BadRequestException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;
    protected final Log logger = LogFactory.getLog(this.getClass());
    @PatchMapping
    public ResponseEntity<?> changePassword(
          @RequestBody ChangePasswordRequest request,
          Principal connectedUser
    ) {
        service.changePassword(request, connectedUser);
        return ResponseEntity.ok().build();
    }
    @Operation(summary = "Update user by Id")

    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Success Register Request",
                    content = {@Content(mediaType = "application/json", schema = @Schema(implementation = AppResponse.class))}),
            @ApiResponse(responseCode = "500", description = "Internal error.", content = @Content)
    })
    @RequestMapping(value = "/updaterUser", method = RequestMethod.PUT)
    public AppResponse UpdateCustomer(@RequestBody RegisterRequest param) throws Exception {
        logger.info("/updaterUser/" + param);
        AppResponse response = new AppResponse();
        try {
            service.updateCustomer(param);
        } catch (Exception e) {
            throw new BadRequestException(e.getMessage());
        }
        return response;
    }

    @Operation(summary = "Delete user by Id")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Success Register Request",
                    content = {@Content(mediaType = "application/json", schema = @Schema(implementation = AppResponse.class))}),
            @ApiResponse(responseCode = "500", description = "Internal error.", content = @Content)
    })
    @RequestMapping(value = "/setStatus", method = RequestMethod.PUT)
    public AppResponse DeleteCustomer(@RequestBody RegisterRequest param) throws Exception {
        logger.info("/setStatus/" + param);
        AppResponse response = new AppResponse();
        try {
            service.updateStatus(param);
        } catch (Exception e) {
            throw new BadRequestException(e.getMessage());
        }
        return response;
    }

    @Operation(summary = "Get all Customers", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AppResponse.class))
            }),
            @ApiResponse(responseCode = "500", description = "Internal error.", content = @Content)
    })
    @RequestMapping(value = "/getCustomers", method = RequestMethod.GET)
    public AppResponse getCustomers() throws Exception {
        logger.debug("/getCustomer" );

        AppResponse response = new AppResponse();
        try {
            List<UserResponse> res = service.getCustomerData();
            response.setData(res);
        } catch (Exception e) {
            throw new BadRequestException(e.getMessage());
        }
        return response;
    }
    @Operation(summary = "Get all users", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = AppResponse.class))
            }),
            @ApiResponse(responseCode = "500", description = "Internal error.", content = @Content)
    })
    @RequestMapping(value = "/getUsers", method = RequestMethod.GET)
    public AppResponse getUsers() throws Exception {
        logger.debug("/getCustomer" );

        AppResponse response = new AppResponse();
        try {
            List<UserResponse> res = service.getUserData();
            response.setData(res);
        } catch (Exception e) {
            throw new BadRequestException(e.getMessage());
        }
        return response;
    }
}
