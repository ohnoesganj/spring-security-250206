package com.example.security;

import com.example.security.domain.member.member.controller.ApiV1MemberController;
import com.example.security.domain.member.member.entity.Member;
import com.example.security.domain.member.member.service.MemberService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Transactional
public class ApiV1MemberControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private MemberService memberService;


    private void checkMember(ResultActions resultActions, Member member) throws Exception {
        resultActions
                .andExpect(jsonPath("$.data").exists())
                .andExpect(jsonPath("$.data.id").value(member.getId()))
                .andExpect(jsonPath("$.data.nickname").value(member.getNickname()))
                .andExpect(jsonPath("$.data.createdDate").value(matchesPattern(member.getCreatedDate().toString().replaceAll("0+$", "") + ".*")))
                .andExpect(jsonPath("$.data.modifiedDate").value(matchesPattern(member.getModifiedDate().toString().replaceAll("0+$", "") + ".*")));
    }

    private ResultActions joinRequest(String username, String password, String nickname) throws Exception {
        return mvc
                .perform(
                        post("/api/v1/members/join")
                                .content("""
                                        {
                                            "username": "%s",
                                            "password": "%s",
                                            "nickname": "%s"
                                        }
                                        """
                                        .formatted(username, password, nickname)
                                        .stripIndent())
                                .contentType(
                                        new MediaType(MediaType.APPLICATION_JSON, StandardCharsets.UTF_8)
                                )
                )
                .andDo(print());
    }

    @Test
    @DisplayName("회원 가입1")
    void join1() throws Exception {

        String username = "userNew";
        String password = "1234";
        String nickname = "무명";

        ResultActions resultActions = joinRequest(username, password, nickname);
        Member member = memberService.findByUsername("userNew").get();

        assertThat(member.getNickname()).isEqualTo(nickname);

        resultActions
                .andExpect(status().isCreated())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("join"))
                .andExpect(jsonPath("$.code").value("201-1"))
                .andExpect(jsonPath("$.msg").value("회원 가입이 완료되었습니다."));

        checkMember(resultActions, member);

    }

    @Test
    @DisplayName("회원 가입2 - username이 이미 존재하는 케이스")
    void join2() throws Exception {

        String username = "user1";
        String password = "1234";
        String nickname = "무명";

        ResultActions resultActions = joinRequest(username, password, nickname);

        resultActions
                .andExpect(status().isConflict())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("join"))
                .andExpect(jsonPath("$.code").value("409-1"))
                .andExpect(jsonPath("$.msg").value("이미 사용중인 아이디입니다."));

    }

    @Test
    @DisplayName("회원 가입3 - 입력 데이터 누락")
    void join3() throws Exception {

        String username = "";
        String password = "";
        String nickname = "";

        ResultActions resultActions = joinRequest(username, password, nickname);

        resultActions
                .andExpect(status().isBadRequest())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("join"))
                .andExpect(jsonPath("$.code").value("400-1"))
                .andExpect(jsonPath("$.msg").value("""
                        nickname : NotBlank : must not be blank
                        password : NotBlank : must not be blank
                        username : NotBlank : must not be blank
                        """.trim().stripIndent()));

    }


    private ResultActions loingRequest(String username, String password) throws Exception {
        return mvc
                .perform(
                        post("/api/v1/members/login")
                                .content("""
                                        {
                                            "username": "%s",
                                            "password": "%s"
                                        }
                                        """
                                        .formatted(username, password)
                                        .stripIndent())
                                .contentType(
                                        new MediaType(MediaType.APPLICATION_JSON, StandardCharsets.UTF_8)
                                )
                )
                .andDo(print());
    }

    @Test
    @DisplayName("로그인 - 성공")
    void login1() throws Exception {

        String username = "user1";
        String password = "user11234";

        // 요청
        ResultActions resultActions = loingRequest(username, password);
        Member member = memberService.findByUsername(username).get();

        // 응답. (요청 처리 결과)
        resultActions
                .andExpect(status().isOk())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(jsonPath("$.code").value("200-1"))
                .andExpect(jsonPath("$.msg").value("%s님 환영합니다.".formatted(member.getNickname())))
                .andExpect(jsonPath("$.data").exists())
                .andExpect(jsonPath("$.data.item.id").value(member.getId()))
                .andExpect(jsonPath("$.data.item.nickname").value(member.getNickname()))
                .andExpect(jsonPath("$.data.item.createdDate").value(member.getCreatedDate().toString()))
                .andExpect(jsonPath("$.data.item.modifiedDate").value(member.getModifiedDate().toString()))
                .andExpect(jsonPath("$.data.apiKey").value(member.getApiKey()));


    }

    @Test
    @DisplayName("로그인 - 실패 - 비밀번호 틀림")
    void login2() throws Exception {

        String username = "user1";
        String password = "1234";

        ResultActions resultActions = loingRequest(username, password);

        resultActions
                .andExpect(status().isUnauthorized())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(jsonPath("$.code").value("401-2"))
                .andExpect(jsonPath("$.msg").value("비밀번호가 일치하지 않습니다."));

    }

    @Test
    @DisplayName("로그인 - 실패 - 존재하지 않는 username")
    void login3() throws Exception {

        String username = "aaaaa";
        String password = "1234";

        ResultActions resultActions = loingRequest(username, password);

        resultActions
                .andExpect(status().isUnauthorized())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(jsonPath("$.code").value("401-1"))
                .andExpect(jsonPath("$.msg").value("잘못된 아이디입니다."));

    }

    @Test
    @DisplayName("로그인 - 실패 - username 누락")
    void login4() throws Exception {

        String username = "";
        String password = "123123";

        ResultActions resultActions = loingRequest(username, password);

        resultActions
                .andExpect(status().isBadRequest())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(jsonPath("$.code").value("400-1"))
                .andExpect(jsonPath("$.msg").value("username : NotBlank : must not be blank"));

    }

    @Test
    @DisplayName("로그인 - 실패 - password 누락")
    void login5() throws Exception {

        String username = "123123";
        String password = "";

        ResultActions resultActions = loingRequest(username, password);

        resultActions
                .andExpect(status().isBadRequest())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(jsonPath("$.code").value("400-1"))
                .andExpect(jsonPath("$.msg").value("password : NotBlank : must not be blank"));

    }

    private ResultActions meRequest(String apiKey) throws Exception {
        return mvc
                .perform(
                        get("/api/v1/members/me")
                                .header("Authorization", "Bearer " + apiKey)

                )
                .andDo(print());
    }

    @Test
    @DisplayName("내 정보 조회")
    void me1() throws Exception {

        String apiKey = "user1";

        ResultActions resultActions = meRequest(apiKey);

        resultActions
                .andExpect(status().isOk())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("me"))
                .andExpect(jsonPath("$.code").value("200-1"))
                .andExpect(jsonPath("$.msg").value("내 정보 조회가 완료되었습니다."));

        Member member = memberService.findByApiKey(apiKey).get();
        checkMember(resultActions, member);

    }

    @Test
    @DisplayName("내 정보 조회 - 실패 - 잘못된 api key")
    void me2() throws Exception {

        String apiKey = "";

        ResultActions resultActions = meRequest(apiKey);

        resultActions
                .andExpect(status().isUnauthorized())
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("me"))
                .andExpect(jsonPath("$.code").value("401-1"))
                .andExpect(jsonPath("$.msg").value("잘못된 인증키입니다."));

    }


}
