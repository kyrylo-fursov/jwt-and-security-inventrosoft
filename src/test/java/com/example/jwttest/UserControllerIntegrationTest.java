package com.example.jwttest;

import com.example.jwttest.entity.AuthRequest;
import com.example.jwttest.entity.TokenRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class UserControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void testWelcome() throws Exception {
        mockMvc.perform(get("/auth/welcome"))
                .andExpect(status().isOk())
                .andExpect(content().string("Welcome, this endpoint is not secure"));
    }

    @Test
    public void testRegisterUser() throws Exception {
        String userInfoJson = "{\"name\":\"testUser\",\"email\":\"test@email.com\",\"password\":\"testPassword\",\"roles\":\"ROLE_USER\"}";

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userInfoJson))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userInfoJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testRegisterUserWithInvalidData() throws Exception {
        String userWithNoEmailInfoJson =
                "{\"name\":\"\"," +
                "\"email\":\"user1@email.com\"," +
                "\"password\":\"testPassword\"," +
                "\"roles\":\"ROLE_USER\"}";

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userWithNoEmailInfoJson));

        String userInfoIsEmpty = "";

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(userInfoIsEmpty))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testLoginReturnsJwtToken() throws Exception {
        AuthRequest authRequest = new AuthRequest("user1", "1234");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    public void testLoginWithInvalidPassword() throws Exception {
        AuthRequest authRequest = new AuthRequest("user1", "wrong_password");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testLoginWithNonExistingUser() throws Exception {
        AuthRequest authRequest = new AuthRequest("non_existing_user", "1234");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testLoginWithInvalidData() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("null"))
                .andExpect(status().isBadRequest());
    }

    String getRefreshTokenForUser(String username, String password) throws Exception {
        AuthRequest authRequest = new AuthRequest(username, password);

        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return objectMapper.readTree(response).get("refreshToken").asText();
    }

    @Test
    public void usersCanRefreshTokens() throws Exception {
        String user1RefreshToken = getRefreshTokenForUser("user1", "1234");

        MvcResult result1 = mockMvc.perform(post("/auth/refreshToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(user1RefreshToken, "user1"))))
                .andExpect(status().isOk())
                .andReturn();

        String responseString = result1.getResponse().getContentAsString();
        JsonNode responseJson = objectMapper.readTree(responseString);
        String newAccessToken = responseJson.get("accessToken").asText();

        mockMvc.perform(get("/auth/user/userProfile")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk());
    }

    @Test
    public void userCannotRefreshAnotherUsersToken() throws Exception {
        String user1RefreshToken = getRefreshTokenForUser("user1", "1234");

        // Attempt to refresh user1's token with user2's credentials
        mockMvc.perform(post("/auth/refreshToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(user1RefreshToken, "user2"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void oldRefreshTokenIsInvalidated() throws Exception {
        String oldRefreshToken = getRefreshTokenForUser("user1", "1234");
        String newRefreshToken = getRefreshTokenForUser("user1", "1234");

        mockMvc.perform(post("/auth/refreshToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(oldRefreshToken, "user1"))))
                .andExpect(status().isUnauthorized());
    }

    public String obtainAccessToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\", \"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        JsonNode jsonNode = objectMapper.readTree(response);
        return jsonNode.get("accessToken").asText();
    }

    @Test
    public void testUserProfile() throws Exception {
        String token = obtainAccessToken("user1", "1234");
        mockMvc.perform(get("/auth/user/userProfile")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Welcome to User Profile"));
    }

    @Test
    public void testAdminProfile() throws Exception {
        String token = obtainAccessToken("admin", "1234");
        mockMvc.perform(get("/auth/admin/adminProfile")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Welcome to Admin Profile"));
    }

    @Test
    public void testWelcomePage() throws Exception {
        mockMvc.perform(get("/auth/welcome"))
                .andExpect(status().isOk())
                .andExpect(content().string("Welcome, this endpoint is not secure"));
    }

    @Test
    public void testUnauthorizedUserProfile() throws Exception {
        mockMvc.perform(get("/auth/user/userProfile")
                        .header("Authorization", "Bearer invalid_access_token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testUnauthorizedAdminProfile() throws Exception {
        String userToken = obtainAccessToken("user1", "1234");
        mockMvc.perform(get("/auth/admin/adminProfile")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testMissingToken() throws Exception {
        mockMvc.perform(get("/auth/user/userProfile"))
                .andExpect(status().isForbidden());
    }
}