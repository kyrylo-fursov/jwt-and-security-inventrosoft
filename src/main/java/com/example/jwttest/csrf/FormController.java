package com.example.jwttest.csrf;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/csrf")
public class FormController {
    @GetMapping("/form")
    public String getForm() {
        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "<head>\n" +
                "    <title>CSRF Form</title>\n" +
                "</head>\n" +
                "<body>\n" +
                "<form action=\"/submit\" method=\"post\">\n" +
                "    <input type=\"hidden\" name=\"_csrf\" value=\"${_csrf.token}\"/>\n" +
                "    <button type=\"submit\">Submit</button>\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>";
    }
}