package oauth2.exemplo.application.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController("/video")
@RequestMapping("/video")
public class TesteController {

	@RequestMapping(value = "/hello")
	public String helloWord() {

		return "Hello Word";
	}

	@RequestMapping(value = "/echo/{echo}")
	public String echoMethod(String echo) {

		return echo;
	}
}
