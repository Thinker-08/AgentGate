package detector

import "github.com/mihiragrawal/agentgate/internal/core"

type signature struct {
	token      string
	class      core.AgentClass
	operator   string
	verifiable bool
}

var signatures = []signature{
	{"gptbot", core.ClassAIAgent, "openai", true},
	{"chatgpt-user", core.ClassAIAgent, "openai", true},
	{"oai-searchbot", core.ClassSearchCrawler, "openai", true},
	{"claudebot", core.ClassAIAgent, "anthropic", true},
	{"claude-user", core.ClassAIAgent, "anthropic", true},
	{"anthropic-ai", core.ClassAIAgent, "anthropic", true},
	{"perplexitybot", core.ClassSearchCrawler, "perplexity", true},
	{"perplexity-user", core.ClassAIAgent, "perplexity", true},
	{"google-extended", core.ClassAIAgent, "google", true},
	{"googlebot", core.ClassSearchCrawler, "google", true},
	{"bingbot", core.ClassSearchCrawler, "microsoft", true},
	{"ccbot", core.ClassSearchCrawler, "commoncrawl", false},
	{"bytespider", core.ClassAIAgent, "bytedance", false},
	{"meta-externalagent", core.ClassAIAgent, "meta", false},
	{"amazonbot", core.ClassSearchCrawler, "amazon", false},
	{"applebot", core.ClassSearchCrawler, "apple", false},
	{"langchain", core.ClassAutomation, "langchain", false},
	{"crewai", core.ClassAutomation, "crewai", false},
	{"browser-use", core.ClassAutomation, "browser-use", false},
	{"llamaindex", core.ClassAutomation, "llamaindex", false},
	{"python-requests", core.ClassAutomation, "", false},
	{"python-httpx", core.ClassAutomation, "", false},
	{"aiohttp", core.ClassAutomation, "", false},
	{"go-http-client", core.ClassAutomation, "", false},
	{"node-fetch", core.ClassAutomation, "", false},
	{"axios", core.ClassAutomation, "", false},
	{"okhttp", core.ClassAutomation, "", false},
	{"curl/", core.ClassAutomation, "", false},
	{"wget/", core.ClassAutomation, "", false},
	{"scrapy", core.ClassAutomation, "", false},
	{"headlesschrome", core.ClassAutomation, "", false},
	{"puppeteer", core.ClassAutomation, "", false},
	{"playwright", core.ClassAutomation, "", false},
	{"selenium", core.ClassAutomation, "", false},
}

var ja4Denylist = map[string]string{}

func VerifiableOperators() []string {
	seen := map[string]bool{}
	var ops []string
	for _, s := range signatures {
		if s.verifiable && s.operator != "" && !seen[s.operator] {
			seen[s.operator] = true
			ops = append(ops, s.operator)
		}
	}
	return ops
}
