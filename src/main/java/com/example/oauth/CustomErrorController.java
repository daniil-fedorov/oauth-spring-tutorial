package com.example.oauth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    String error(HttpServletRequest request, Exception exception) {
        String header = (String) request.getSession().getAttribute("error.message");

        request.getSession().removeAttribute("error.message");

        return header;
    }

}
