#nullable enable

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Dom;
using RebootRouter.Properties;

namespace RebootRouter {

    internal class RouterRebooter {

        private readonly CookieContainer cookieContainer = new CookieContainer();
        private readonly Settings settings = Settings.Default;
        private readonly HttpClient httpClient;

        private RouterRebooter() {
            var httpClientHandler = new HttpClientHandler {
                UseCookies = true,
                CookieContainer = cookieContainer,
                UseProxy = false
            };
            httpClientHandler.Proxy = httpClientHandler.UseProxy ? new WebProxy("127.0.0.1", 9998) : default;
            httpClient = new HttpClient(httpClientHandler);
        }

        private UriBuilder baseUri => new UriBuilder()
            .WithHost(settings.routerHost);

        private static async Task<int> Main() {
            try {
                await new RouterRebooter().rebootRouter();
                return 0;
            } catch (AuthenticationException e) {
                Console.WriteLine(e.Message);
                return -1;
            }
        }

        private async Task rebootRouter() {
            string sessionId = await logIn();
            await reboot(sessionId);
        }

        private async Task<string> logIn() {
            Console.WriteLine($"Logging in to TP-Link Archer C7 v2 router {settings.routerHost} as {settings.routerUsername}...");

            using var md5 = MD5.Create();
            string password = settings.routerPassword;
            string truncatedPassword = password.Substring(0, Math.Min(15, password.Length));
            byte[] passwordMd5Bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(truncatedPassword));
            string passwordMd5String = BitConverter.ToString(passwordMd5Bytes).Replace("-", string.Empty).ToLower();
            string passwordBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{settings.routerUsername}:{passwordMd5String}"));
            string authCookieHeaderValue = Uri.EscapeDataString("Basic " + passwordBase64);
            cookieContainer.Add(new Cookie("Authorization", authCookieHeaderValue, "/", settings.routerHost));

            Uri requestUri = baseUri
                .WithPathSegment("userRpm")
                .WithPathSegment("LoginRpm.htm")
                .WithParameter("Save", "Save")
                .Uri;

            using HttpResponseMessage response = await httpClient.GetAsync(requestUri);
            response.EnsureSuccessStatusCode();

            IBrowsingContext browsingContext = BrowsingContext.New();
            using Stream responseStream = await response.Content.ReadAsStreamAsync();
            using IDocument responseDocument = await browsingContext.OpenAsync(res => { res.Content(responseStream); });

            var scriptElement = (IHtmlScriptElement) responseDocument.QuerySelector("script");
            Match scriptMatch = Regex.Match(scriptElement.Text, @"window\.parent\.location\.href = ""(.+)"";");
            if (!scriptMatch.Success) {
                throw new AuthenticationException("Could not log in to router (no matching script snippet).");
            }

            try {
                string urlWithSessionId = scriptMatch.Groups[1].Value;
                string sessionId = new Uri(urlWithSessionId).Segments.ElementAt(1).TrimEnd('/');
                Console.WriteLine("Logged in.");
                return sessionId;
            } catch (ArgumentOutOfRangeException) {
                throw new AuthenticationException("Could not log in to router (URL path is /).");
            }
        }

        private async Task reboot(string sessionId) {
            Console.WriteLine("Rebooting router...");

            UriBuilder rebootPage = baseUri
                .WithPathSegment(sessionId)
                .WithPathSegment("userRpm")
                .WithPathSegment("SysRebootRpm.htm");

            Uri rebootCommand = rebootPage
                .WithParameter("Reboot", "Reboot")
                .Uri;

            using var request = new HttpRequestMessage(HttpMethod.Get, rebootCommand);
            request.Headers.Referrer = rebootPage.Uri;

            using HttpResponseMessage response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            Console.WriteLine("Router is rebooting.");
        }

    }

}