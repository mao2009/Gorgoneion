using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Gorgoneion;

public static class ReadOnlyProbeTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _reply;
        public int Requests { get; private set; }
        public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> reply)
            => _reply = reply;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return _reply(request, cancellationToken);
        }
    }

    private static HttpResponseMessage Reply(HttpStatusCode status, string body = "{}") =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static async Task<int> RunAsync()
    {
        var count = 0;
        void Check(bool condition, string name)
        {
            count++;
            if (!condition) throw new Exception("FAIL: " + name);
        }

        var opn = new IntegrationTarget("lab-firewall", "opnsense.preview", "https://192.168.1.1/", true, true);
        var st2 = new IntegrationTarget("lab-soar", "stackstorm.preview", "https://127.0.0.1/", true, true);
        string? observed = null;
        var handler = new StubHandler((request, _) =>
        {
            Check(request.Method == HttpMethod.Get, "probe is GET only");
            Check(request.RequestUri?.AbsolutePath == "/api/core/system/status", "OPNsense path matches official endpoint");
            Check(request.Headers.Authorization?.Scheme == "Basic", "OPNsense basic scheme");
            observed = Encoding.UTF8.GetString(Convert.FromBase64String(
                request.Headers.Authorization!.Parameter!));
            return Task.FromResult(Reply(HttpStatusCode.OK, "{\"status\":\"ok\"}"));
        });
        using (var client = new HttpMessageInvoker(handler))
        {
            var result = await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "key", "secret", client);
            Check(result.Success && result.Code == "read_only_schema_observed", "OPNsense mocked GET success");
            Check(result.RecordsObserved is null, "OPNsense JSON object accepted");
            Check(result.ToString()!.Contains("secret") == false, "secret never in probe result");
        }
        Check(observed == "key:secret", "basic credentials sent in header");

        var stackHandler = new StubHandler((request, _) =>
        {
            Check(request.Method == HttpMethod.Get, "StackStorm GET only");
            Check(request.RequestUri?.PathAndQuery == "/api/v1/actions?limit=1", "StackStorm API path matches official endpoint");
            Check(request.Headers.TryGetValues("St2-Api-Key", out var values)
                && values.Single() == "api-test", "StackStorm API key header");
            Check(request.Headers.Authorization is null, "no duplicate auth");
            return Task.FromResult(Reply(HttpStatusCode.OK, "[{\"name\":\"fake-action\"}]"));
        });
        using (var client = new HttpMessageInvoker(stackHandler))
        {
            var result = await ReadOnlyApiProbe.ProbeStackStormAsync(st2, "api-test", client);
            Check(result.Success && result.RecordsObserved == 1, "StackStorm mocked list parsed");
        }

        async Task<ApiProbeResult> WithStatus(HttpStatusCode status, string json = "{}")
        {
            using var transport = new HttpMessageInvoker(
                new StubHandler((_, _) => Task.FromResult(Reply(status, json))));
            return await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "key", "secret", transport);
        }

        Check((await WithStatus(HttpStatusCode.Unauthorized)).Code == "authentication_or_permission_denied",
            "401 refused");
        Check((await WithStatus(HttpStatusCode.Forbidden)).Code == "authentication_or_permission_denied",
            "403 refused");
        Check((await WithStatus(HttpStatusCode.TooManyRequests)).Code == "rate_limited", "429 handled");
        Check((await WithStatus(HttpStatusCode.ServiceUnavailable)).Code == "http_error", "503 handled");
        Check((await WithStatus(HttpStatusCode.Redirect)).Code == "redirect_refused", "redirect refused");
        Check((await WithStatus(HttpStatusCode.OK, "[]")).Code == "unexpected_json_shape", "wrong shape denied");
        Check((await WithStatus(HttpStatusCode.OK, "{nope")).Code == "invalid_json", "bad JSON denied");
        Check((await WithStatus(HttpStatusCode.OK, new string('X', 17000))).Code == "response_too_large",
            "bounded payload handling");

        // A forged small Content-Length must not bypass the streaming byte limit.
        var oversized = new StubHandler((_, _) =>
        {
            var response = Reply(HttpStatusCode.OK, new string('A', 17000));
            response.Content.Headers.ContentLength = 10;
            return Task.FromResult(response);
        });
        using (var client = new HttpMessageInvoker(oversized))
        {
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "k", "s", client)).Code == "response_too_large",
                "streaming limit independently enforced");
        }

        var deniedHandler = new StubHandler((_, _) =>
            Task.FromResult(Reply(HttpStatusCode.OK)));
        using (var client = new HttpMessageInvoker(deniedHandler))
        {
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn with { Owned = false },
                "key", "secret", client)).Code == "target_not_enabled_or_owned", "unowned target rejected");
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn with { BaseUrl = "https://8.8.8.8/" },
                "key", "secret", client)).Code == "endpoint_not_lab_or_private", "public IP rejected");
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "", "secret", client)).Code
                == "missing_or_invalid_credentials", "empty credentials rejected");
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(st2, "key", "secret", client)).Code
                == "adapter_mismatch", "adapter cannot cross endpoints");
            Check(deniedHandler.Requests == 0, "invalid probes produce no HTTP messages");
        }

        using (var client = new HttpMessageInvoker(new StubHandler((_, _) =>
            throw new HttpRequestException("secret from HTTP exception"))))
        {
            var result = await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "key", "secret", client);
            Check(result.Code == "transport_error", "transport exception sanitized");
            Check(!result.ToString()!.Contains("secret", StringComparison.Ordinal), "transport secret redacted");
        }

        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel();
            using var client = new HttpMessageInvoker(new StubHandler((_, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(Reply(HttpStatusCode.OK));
            }));
            Check((await ReadOnlyApiProbe.ProbeOpnsenseAsync(opn, "key", "secret", client,
                cancelled.Token)).Code == "cancelled", "caller cancellation handled");
        }
        Console.WriteLine($"PASS: {count} simulated HTTP assertions; no sockets or live APIs used.");
        return count;
    }
}
