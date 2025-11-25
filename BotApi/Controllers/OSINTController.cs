using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace BotApi.Controllers
{
    [ApiController]
    [Route("api/osint")]
    public class AdvancedOSINTController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        // Social Media Platforms
        private static readonly Dictionary<string, PlatformInfo> SocialMediaPlatforms = new()
        {
            { "GitHub", new PlatformInfo { Url = "https://www.github.com/{0}", ApiUrl = "https://api.github.com/users/{0}", Category = "Development" } },
            { "Instagram", new PlatformInfo { Url = "https://www.instagram.com/{0}", Category = "Social Media" } },
            { "Twitter/X", new PlatformInfo { Url = "https://www.twitter.com/{0}", Category = "Social Media" } },
            { "LinkedIn", new PlatformInfo { Url = "https://www.linkedin.com/in/{0}", Category = "Professional" } },
            { "Reddit", new PlatformInfo { Url = "https://www.reddit.com/user/{0}", Category = "Community" } },
            { "TikTok", new PlatformInfo { Url = "https://www.tiktok.com/@{0}", Category = "Social Media" } },
            { "YouTube", new PlatformInfo { Url = "https://www.youtube.com/@{0}", Category = "Video" } },
            { "Facebook", new PlatformInfo { Url = "https://www.facebook.com/{0}", Category = "Social Media" } },
            { "Twitch", new PlatformInfo { Url = "https://www.twitch.tv/{0}", Category = "Streaming" } },
            { "Medium", new PlatformInfo { Url = "https://medium.com/@{0}", Category = "Blogging" } },
            { "Telegram", new PlatformInfo { Url = "https://t.me/{0}", Category = "Messaging" } },
            { "Discord", new PlatformInfo { Url = "https://discord.gg/", Category = "Messaging" } },
            { "Mastodon", new PlatformInfo { Url = "https://mastodon.social/@{0}", Category = "Social Media" } },
            { "Patreon", new PlatformInfo { Url = "https://www.patreon.com/{0}", Category = "Creator" } },
            { "Kickstarter", new PlatformInfo { Url = "https://www.kickstarter.com/profile/{0}", Category = "Funding" } },
            { "Spotify", new PlatformInfo { Url = "https://open.spotify.com/user/{0}", Category = "Music" } },
            { "Dribbble", new PlatformInfo { Url = "https://dribbble.com/{0}", Category = "Design" } },
            { "Behance", new PlatformInfo { Url = "https://www.behance.net/{0}", Category = "Design" } },
            { "DeviantArt", new PlatformInfo { Url = "https://www.deviantart.com/{0}", Category = "Art" } },
            { "Flickr", new PlatformInfo { Url = "https://www.flickr.com/photos/{0}", Category = "Photography" } },
            { "500px", new PlatformInfo { Url = "https://500px.com/{0}", Category = "Photography" } },
            { "Untappd", new PlatformInfo { Url = "https://untappd.com/user/{0}", Category = "Lifestyle" } },
            { "Goodreads", new PlatformInfo { Url = "https://www.goodreads.com/{0}", Category = "Reading" } },
            { "Steam", new PlatformInfo { Url = "https://steamcommunity.com/search/users/#text={0}", Category = "Gaming" } },
            { "Xbox Live", new PlatformInfo { Url = "https://xboxgamertag.com/search/{0}", Category = "Gaming" } },
            { "PlayStation", new PlatformInfo { Url = "https://psnprofiles.com/{0}", Category = "Gaming" } },
            { "Slack", new PlatformInfo { Url = "https://slack.com{0}", Category = "Messaging" } },
            { "Stack Overflow", new PlatformInfo { Url = "https://stackoverflow.com/users/{0}", Category = "Development" } },
            { "GitLab", new PlatformInfo { Url = "https://gitlab.com/{0}", Category = "Development" } },
            { "Bitbucket", new PlatformInfo { Url = "https://bitbucket.org/{0}", Category = "Development" } },
            { "VK (Vkontakte)", new PlatformInfo { Url = "https://vk.com/{0}", Category = "Social Media (Eurasia)" } },
            { "Odnoklassniki", new PlatformInfo { Url = "https://ok.ru/profile/{0}", Category = "Social Media (Eurasia)" } },
            { "Mail.ru/MyWorld", new PlatformInfo { Url = "https://my.mail.ru/mail/{0}/", Category = "Social Media/Messaging" } },
            { "GetContact", new PlatformInfo { Url = "https://www.getcontact.com/az/q/{0}", Category = "Utility (Search Link)" } },
        };

        // Dark Web & Forum Platforms
        private static readonly Dictionary<string, PlatformInfo> ForumsPlatforms = new()
        {
            { "Reddit", new PlatformInfo { Url = "https://www.reddit.com/user/{0}", Category = "Forum" } },
            { "Stack Overflow", new PlatformInfo { Url = "https://stackoverflow.com/users/{0}", Category = "Q&A" } },
            { "Quora", new PlatformInfo { Url = "https://www.quora.com/profile/{0}", Category = "Q&A" } },
            { "Medium", new PlatformInfo { Url = "https://medium.com/@{0}", Category = "Blogging" } },
            { "Blogger", new PlatformInfo { Url = "https://www.blogger.com/profile/{0}", Category = "Blogging" } }
        };

        public AdvancedOSINTController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        // --- ENDPOINTS ---

        /// <summary>
        /// Comprehensive Investigation (POST) - Email Breach Scoring Removed.
        /// </summary>
        [HttpPost("investigate")]
        public async Task<IActionResult> InvestigateUsername([FromBody] InvestigationRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Query))
                return BadRequest(new { error = "Search query cannot be empty" });

            // Remove all whitespaces from the query for platform searches
            string cleanedQuery = Regex.Replace(request.Query, @"\s+", "");

            var results = new InvestigationResult
            {
                SearchQuery = request.Query,
                SearchTimestamp = DateTime.UtcNow,
                Results = new Dictionary<string, object>(),
                RiskScore = 0
            };

            int riskScore = 0;

            // 1. Username search - Social Media
            if (request.SearchSocialMedia != false)
            {
                // Use cleanedQuery for username searches
                var socialResults = await SearchUsernameOnPlatforms(cleanedQuery, SocialMediaPlatforms);
                results.Results["social_media"] = socialResults;

                // Risk Scoring: +5 points for each found social media profile
                riskScore += socialResults.Count(r => (bool)((dynamic)r).found) * 5;
            }

            // 2. Email search (Use original query)
            if (request.SearchEmails != false && IsValidEmail(request.Query))
            {
                var emailAnalysis = AnalyzeEmail(request.Query);
                var breachData = await CheckForBreaches(request.Query);

                emailAnalysis["breach_data"] = breachData;
                results.Results["email_analysis"] = emailAnalysis;

                // IMPORTANT: Email breach scoring remains REMOVED.
            }

            // 3. IP search (Use original query)
            if (request.SearchIP != false && IsValidIP(request.Query))
            {
                results.Results["ip_information"] = await GetIPInformation(request.Query);
            }

            // 4. Domain search (Use original query)
            if (request.SearchDomains != false && IsValidDomain(request.Query))
            {
                results.Results["domain_information"] = await GetDomainInformation(request.Query);
            }

            // 5. Phone number search (Use original query)
            if (request.SearchPhone != false && IsValidPhoneNumber(request.Query))
            {
                results.Results["phone_information"] = AnalyzePhoneNumber(request.Query);
            }

            // 6. Bitcoin address search (Use original query)
            if (request.SearchCrypto != false && IsValidBitcoinAddress(request.Query))
            {
                results.Results["bitcoin_information"] = GetBitcoinInformation(request.Query);
            }

            // 7. Forum/Community search
            if (request.SearchForums != false)
            {
                // Use cleanedQuery for forum searches
                var forumResults = await SearchUsernameOnPlatforms(cleanedQuery, ForumsPlatforms);
                results.Results["forum_profiles"] = forumResults;
                // Risk Scoring: +3 points for each found forum profile
                riskScore += forumResults.Count(r => (bool)((dynamic)r).found) * 3;
            }

            // 8. Name-based search (Use original query)
            if (request.SearchNames != false && !IsValidIP(request.Query) && !IsValidEmail(request.Query))
            {
                results.Results["name_search"] = await SearchByName(request.Query);
            }

            results.RiskScore = riskScore;

            // Risk Level Mapping (Based only on social media and forum scores)
            if (riskScore > 15)
                results.Results["risk_level"] = "MEDIUM";
            else
                results.Results["risk_level"] = "LOW";

            return Ok(results);
        }

        /// <summary>
        /// Dedicated Username Search (GET)
        /// </summary>
        [HttpGet("username/{username}")]
        public async Task<IActionResult> GetUsernameDetails(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return BadRequest(new { error = "Username cannot be empty." });

            // Remove all whitespaces from the username for platform searches
            string cleanedUsername = Regex.Replace(username, @"\s+", "");

            var socialMediaResults = await SearchUsernameOnPlatforms(cleanedUsername, SocialMediaPlatforms);
            var forumResults = await SearchUsernameOnPlatforms(cleanedUsername, ForumsPlatforms);

            int riskScore = (socialMediaResults.Count(r => (bool)((dynamic)r).found) * 5) +
                            (forumResults.Count(r => (bool)((dynamic)r).found) * 3);

            return Ok(new
            {
                search_query = username,
                search_timestamp = DateTime.UtcNow,
                risk_score = riskScore,
                risk_level = riskScore > 15 ? "MEDIUM" : "LOW",
                social_media = socialMediaResults,
                forums_and_community = forumResults
            });
        }

        /// <summary>
        /// Dedicated Email Deep Investigation (GET) - Breach scoring removed.
        /// </summary>
        [HttpGet("email-details/{email}")]
        public async Task<IActionResult> GetEmailDetails(string email)
        {
            if (!IsValidEmail(email))
                return BadRequest(new { error = "Invalid email address" });

            var emailAnalysis = AnalyzeEmail(email);
            var breachData = await CheckForBreaches(email);

            // Since email breach scoring was removed, the score is set to 0.
            int riskScore = 0;

            return Ok(new
            {
                search_query = email,
                search_timestamp = DateTime.UtcNow,
                risk_score = riskScore,
                risk_level = riskScore > 15 ? "MEDIUM" : "LOW",
                email_analysis = emailAnalysis,
                breach_data = breachData
            });
        }

        /// <summary>
        /// IP Address Deep Investigation
        /// </summary>
        [HttpGet("ip-details/{ipAddress}")]
        public async Task<IActionResult> GetIPDetails(string ipAddress)
        {
            if (!IsValidIP(ipAddress))
                return BadRequest(new { error = "Invalid IP address" });

            var ipInfo = await GetIPInformation(ipAddress);

            return Ok(new
            {
                ip = ipAddress,
                information = ipInfo,
                lookup_services = new Dictionary<string, string>
                {
                    { "abuseipdb", $"https://www.abuseipdb.com/check/{ipAddress}" },
                    { "shodan", $"https://www.shodan.io/host/{ipAddress}" },
                    { "censys", $"https://censys.io/ipv4/{ipAddress}" },
                    { "ipqualityscore", $"https://ipqualityscore.com/api/json/ip/{ipAddress}" }
                },
                timestamp = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Domain WHOIS & DNS Information
        /// </summary>
        [HttpGet("domain-details/{domain}")]
        public async Task<IActionResult> GetDomainDetails(string domain)
        {
            if (!IsValidDomain(domain))
                return BadRequest(new { error = "Invalid domain" });

            var domainInfo = await GetDomainInformation(domain);

            return Ok(new
            {
                domain = domain,
                information = domainInfo,
                lookup_services = new Dictionary<string, string>
                {
                    { "whois", $"https://www.whois.com/whois/{domain}" },
                    { "shodan", $"https://www.shodan.io/search?query={domain}" },
                    { "crt.sh", $"https://crt.sh/?q=%25.{domain}" },
                    { "dnsdumpster", $"https://dnsdumpster.com/" },
                    { "dnsrecon", "https://www.dnsrecon.io/" }
                },
                timestamp = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Reverse Phone Number Lookup
        /// </summary>
        [HttpGet("phone/{phoneNumber}")]
        public IActionResult GetPhoneDetails(string phoneNumber)
        {
            if (!IsValidPhoneNumber(phoneNumber))
                return BadRequest(new { error = "Invalid phone number" });

            return Ok(new
            {
                phone = phoneNumber,
                information = AnalyzePhoneNumber(phoneNumber),
                lookup_services = new Dictionary<string, string>
                {
                    { "truecaller", "https://www.truecaller.com/" },
                    { "whitepages", "https://www.whitepages.com/" },
                    { "znumbers", "https://www.znumbers.com/" }
                },
                timestamp = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Bitcoin Address Analysis
        /// </summary>
        [HttpGet("bitcoin/{address}")]
        public IActionResult GetBitcoinDetails(string address)
        {
            if (!IsValidBitcoinAddress(address))
                return BadRequest(new { error = "Invalid Bitcoin address" });

            return Ok(new
            {
                address = address,
                information = GetBitcoinInformation(address),
                explorers = new Dictionary<string, string>
                {
                    { "blockchain", $"https://www.blockchain.com/btc/address/{address}" },
                    { "blockchair", $"https://blockchair.com/bitcoin/address/{address}" },
                    { "etherscan", $"https://etherscan.io/address/{address}" },
                    { "blockscout", $"https://blockscout.com/eth/mainnet/address/{address}" }
                },
                timestamp = DateTime.UtcNow
            });
        }

        // --- HELPER METHODS ---

        private HttpClient GetOSINTHttpClient()
        {
            if (_httpClientFactory == null)
            {
                throw new InvalidOperationException("IHttpClientFactory service is not configured.");
            }

            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36");
            client.Timeout = TimeSpan.FromSeconds(8);
            return client;
        }

        private async Task<List<string>> CheckForBreaches(string email)
        {
            var breaches = new List<string>();
            // This section should be integrated with a real API (e.g., Have I Been Pwned).
            // Currently, only sample data is returned.
            if (email.Contains("riski_var"))
            {
                breaches.Add("LinkedIn Breach (2012)");
                breaches.Add("Adobe Breach (2013)");
            }
            else if (email.Contains("test"))
            {
                breaches.Add("Sample Forum Breach (2020)");
            }
            return breaches;
        }

        private Dictionary<string, object> AnalyzeEmail(string email)
        {
            var domain = email.Split('@')[1].ToLower();
            var providers = new Dictionary<string, string>
            {
                { "gmail.com", "Google - High Security" },
                { "hotmail.com", "Microsoft - Medium Security" },
                { "outlook.com", "Microsoft - Medium Security" },
                { "yahoo.com", "Yahoo - Low Security" }
            };

            return new Dictionary<string, object>
            {
                { "email", email },
                { "domain", domain },
                { "is_public_provider", providers.ContainsKey(domain) },
                { "provider_info", providers.ContainsKey(domain) ? providers[domain] : "Private/Corporate Domain" }
            };
        }


        private async Task<List<object>> SearchUsernameOnPlatforms(string username, Dictionary<string, PlatformInfo> platforms)
        {
            var results = new List<object>();
            var client = GetOSINTHttpClient();

            foreach (var platform in platforms)
            {
                string url = string.Format(platform.Value.Url, username);
                string status = "Not Checked";
                bool found = false;

                try
                {
                    using var response = await client.GetAsync(url);
                    int statusCode = (int)response.StatusCode;

                    if (response.IsSuccessStatusCode)
                    {
                        string content = await response.Content.ReadAsStringAsync();

                        if (platform.Key == "Instagram" || platform.Key == "Twitter/X")
                        {
                            // Simple content check
                            if (content.Contains("Page Not Found") || content.Contains("Sorry, this page isn't available") || content.Contains("Hesap bulunamadı"))
                            {
                                status = "Not Found (Content Check)";
                                found = false;
                            }
                            else
                            {
                                status = "Found (Content Check)";
                                found = true;
                            }
                        }
                        else if (platform.Key == "GitHub")
                        {
                            // API usage example
                            if (platform.Value.ApiUrl != null)
                            {
                                var apiResponse = await client.GetAsync(string.Format(platform.Value.ApiUrl, username));
                                found = apiResponse.IsSuccessStatusCode;
                                status = found ? "Found (API)" : "Not Found (API)";
                            }
                            else
                            {
                                status = "Found (HTTP 200)";
                                found = true;
                            }
                        }
                        else
                        {
                            status = "Found (HTTP 200)";
                            found = true;
                        }
                    }
                    else if (statusCode == 404)
                    {
                        status = "Not Found (HTTP 404)";
                        found = false;
                    }
                    else
                    {
                        status = $"Unexpected Status ({statusCode})";
                        found = false;
                    }
                }
                catch (TaskCanceledException)
                {
                    status = "Connection Error (Timeout)";
                    found = false;
                }
                catch (HttpRequestException)
                {
                    status = "Connection Error (Network/DNS)";
                    found = false;
                }
                catch (Exception)
                {
                    status = "Unknown Error";
                    found = false;
                }

                results.Add(new
                {
                    platform = platform.Key,
                    category = platform.Value.Category,
                    profile_url = url,
                    found = found,
                    status_check = status
                });
            }
            return results;
        }

        private async Task<Dictionary<string, object>> GetIPInformation(string ip)
        {
            var client = GetOSINTHttpClient();
            try
            {
                var response = await client.GetAsync($"https://ipapi.co/{ip}/json/");
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return new Dictionary<string, object>
                    {
                        { "ip", ip },
                        { "data", content }
                    };
                }
            }
            catch { }

            return new Dictionary<string, object> { { "ip", ip }, { "status", "Unable to fetch" } };
        }

        private async Task<Dictionary<string, object>> GetDomainInformation(string domain)
        {
            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(domain);
                return new Dictionary<string, object>
                {
                    { "domain", domain },
                    { "ip_addresses", hostEntry.AddressList.Select(ip => ip.ToString()).ToList() },
                    { "aliases", hostEntry.Aliases.ToList() }
                };
            }
            catch { }

            return new Dictionary<string, object> { { "domain", domain }, { "status", "Unable to resolve" } };
        }

        private async Task<List<object>> SearchByName(string name)
        {
            var results = new List<object>
            {
                new { search_engine = "Google", url = $"https://www.google.com/search?q=\"{name}\"" },
                new { search_engine = "Bing", url = $"https://www.bing.com/search?q=\"{name}\"" },
                new { search_engine = "DuckDuckGo", url = $"https://duckduckgo.com/?q=\"{name}\"" }
            };
            return results;
        }

        private Dictionary<string, object> AnalyzePhoneNumber(string phone)
        {
            return new Dictionary<string, object>
            {
                { "phone", phone },
                { "lookup_available", true },
                { "services", new[] { "TrueCaller", "WhitePages", "ZNumbers" } }
            };
        }

        private Dictionary<string, object> GetBitcoinInformation(string address)
        {
            return new Dictionary<string, object>
            {
                { "address", address },
                { "type", address.Length == 26 || address.Length == 35 ? "Bitcoin Address" : "Unknown" },
                { "blockchain_explorers", new[] { "Blockchain.com", "BlockChair", "BlockScout" } }
            };
        }

        // Validation Methods
        private bool IsValidIP(string ip) => IPAddress.TryParse(ip, out _);
        private bool IsValidDomain(string domain) => Regex.IsMatch(domain, @"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$");
        private bool IsValidEmail(string email) => Regex.IsMatch(email, @"^[^\s@]+@[^\s@]+\.[^\s@]+$");
        private bool IsValidPhoneNumber(string phone) => Regex.IsMatch(phone, @"^\+?[\d\s\-\(\)]{10,}$");
        private bool IsValidBitcoinAddress(string address) => Regex.IsMatch(address, @"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$");
    }

    // --- MODELS ---

    public class PlatformInfo
    {
        public string Url { get; set; }
        public string? ApiUrl { get; set; }
        public string Category { get; set; }
    }

    public class InvestigationRequest
    {
        [JsonPropertyName("query")]
        public string Query { get; set; }

        [JsonPropertyName("search_social_media")]
        public bool? SearchSocialMedia { get; set; } = true;

        [JsonPropertyName("search_emails")]
        public bool? SearchEmails { get; set; } = true;

        [JsonPropertyName("search_ip")]
        public bool? SearchIP { get; set; } = true;

        [JsonPropertyName("search_domains")]
        public bool? SearchDomains { get; set; } = true;

        [JsonPropertyName("search_phone")]
        public bool? SearchPhone { get; set; } = true;

        [JsonPropertyName("search_crypto")]
        public bool? SearchCrypto { get; set; } = true;

        [JsonPropertyName("search_forums")]
        public bool? SearchForums { get; set; } = true;

        [JsonPropertyName("search_names")]
        public bool? SearchNames { get; set; } = true;
    }

    public class InvestigationResult
    {
        [JsonPropertyName("search_query")]
        public string SearchQuery { get; set; }

        [JsonPropertyName("search_timestamp")]
        public DateTime SearchTimestamp { get; set; }

        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }

        [JsonPropertyName("results")]
        public Dictionary<string, object> Results { get; set; }
    }
}