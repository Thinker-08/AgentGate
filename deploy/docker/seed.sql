INSERT INTO policies (host, path_pattern, method, action, price_atomic, network, asset, pay_to, grant_ttl_s, grant_on, bot_class_rules, priority)
VALUES
  ('*', '/public/*',         '*', 'allow', NULL,  'base-sepolia', NULL, NULL, 120, 'settle', NULL, 50),
  ('*', '/content/free/*',   '*', 'allow', NULL,  'base-sepolia', NULL, NULL, 120, 'settle', NULL, 110),
  ('*', '/content/*',        '*', 'pay',   10000, 'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_search_crawler":"allow"}', 100),
  ('*', '/news/*',           '*', 'pay',   8000,  'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_search_crawler":"allow","ai_agent":"deny"}', 100),
  ('*', '/articles/*',       '*', 'pay',   10000, 'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_search_crawler":"allow","verified_google":"deny"}', 100),
  ('*', '/api/*',            '*', 'pay',   20000, 'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"automation_framework":"deny","unknown":"deny"}', 100),
  ('*', '/feed/*',           '*', 'pay',   5000,  'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_search_crawler":"allow","automation_framework":"deny","bytedance":"deny"}', 100),
  ('*', '/partner/openai/*', '*', 'pay',   10000, 'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_openai":"allow"}', 100),
  ('*', '/docs/*',           '*', 'pay',   5000,  'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"human":"allow","verified_search_crawler":"allow"}', 100),
  ('*', '/premium/*',        '*', 'pay',   10000, 'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 120, 'settle', '{"verified_search_crawler":"allow"}', 100),
  ('*', '/research/*',       '*', 'pay',   5000,  'base-sepolia', '0x036CbD53842c5426634e7929541eC2318f3dCF7e', '0x209693Bc6afc0C5328bA36FaF03C514EF312287C', 300, 'settle', '{"verified_search_crawler":"allow"}', 100),
  ('*', '/blocked/*',        '*', 'deny',  NULL,  'base-sepolia', NULL, NULL, 120, 'settle', NULL, 100)
ON CONFLICT DO NOTHING;
