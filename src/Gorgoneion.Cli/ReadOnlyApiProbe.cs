using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Gorgoneion;

/// <summary>
/// Result metadata only. Never expose authentication material or raw response bodies.
/// </summary>
public sealed record ApiProbeResult(string Adapter, string TargetId, bool Success,
    string Code, int? HttpStatusCode = null, int? RecordsObserved = null);

/// <summary>
/// Read-only API discovery for explicitly injected HTTP transports.
/// The CLI does not instantiate a network transport or expose these probes.
/// No POST/PUT/DELETE or defensive enforcement path exists here.
/// </summary>
public static class ReadOnlyApiProbe
{
    private const int MaxResponseBytes = 16 * 1024;
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);

    public static Task<ApiProbeResult> ProbeOpnsenseAsync(
        IntegrationTarget target, string apiKey, string apiSecret,
        HttpMessageInvoker transport, CancellationToken cancellationToken = default)
    {
        if (!ValidCredential(apiKey) || !ValidCredential(apiSecret))
            return Task.FromResult(Failure(target, "missing_or_invalid_credentials"));
        var value = Convert.ToBase64String(Encoding.UTF8.GetBytes(apiKey + ":" + apiSecret));
        return ProbeCoreAsync(target, "opnsense.preview",
            "api/core/system/status", new AuthenticationHeaderValue("Basic", value),
            null, JsonValueKind.Object, transport, cancellationToken);
    }

    public static Task<ApiProbeResult> ProbeStackStormAsync(
        IntegrationTarget target, string apiKey,
        HttpMessageInvoker transport, CancellationToken cancellationToken = default)
    {
        if (!ValidCredential(apiKey))
            return Task.FromResult(Failure(target, "missing_or_invalid_credentials"));
        return ProbeCoreAsync(target, "stackstorm.preview",
            "api/v1/actions?limit=1", null, apiKey, JsonValueKind.Array,
            transport, cancellationToken);
    }

    private static bool ValidCredential(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 4096 &&
        !value.Contains('\r') && !value.Contains('\n') && !value.Contains('\0');

    private static ApiProbeResult Failure(IntegrationTarget? target, string reason,
        int? status = null) =>
        new(target?.Adapter ?? "", target?.Id ?? "", false, reason, status);

    private static async Task<ApiProbeResult> ProbeCoreAsync(
        IntegrationTarget target, string requiredAdapter, string relativePath,
        AuthenticationHeaderValue? basic, string? stackstormKey, JsonValueKind expectedShape,
        HttpMessageInvoker transport, CancellationToken cancellationToken)
    {
        var contract = IntegrationContracts.Validate(target);
        if (!contract.Valid) return Failure(target, contract.Reason);
        if (target.Adapter != requiredAdapter) return Failure(target, "adapter_mismatch");

        // No credentials, URLs or response contents are ever included in diagnostics.
        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(new Uri(target.BaseUrl, UriKind.Absolute), relativePath));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (basic is not null) request.Headers.Authorization = basic;
        if (stackstormKey is not null) request.Headers.Add("St2-Api-Key", stackstormKey);

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(ProbeTimeout);
        try
        {
            using var response = await transport.SendAsync(request, budget.Token).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            if (status is >= 300 and <= 399)
                return Failure(target, "redirect_refused", status);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return Failure(target, "authentication_or_permission_denied", status);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                return Failure(target, "rate_limited", status);
            if (!response.IsSuccessStatusCode)
                return Failure(target, "http_error", status);

            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
                return Failure(target, "response_too_large", status);

            await using var body = await response.Content.ReadAsStreamAsync(budget.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var block = new byte[4096];
            while (true)
            {
                var n = await body.ReadAsync(block.AsMemory(), budget.Token).ConfigureAwait(false);
                if (n == 0) break;
                if (buffer.Length + n > MaxResponseBytes)
                    return Failure(target, "response_too_large", status);
                buffer.Write(block, 0, n);
            }

            buffer.Position = 0;
            using var json = JsonDocument.Parse(buffer,
                new JsonDocumentOptions { MaxDepth = 16 });
            if (json.RootElement.ValueKind != expectedShape)
                return Failure(target, "unexpected_json_shape", status);

            var count = expectedShape == JsonValueKind.Array
                ? json.RootElement.GetArrayLength() : (int?)null;
            return new ApiProbeResult(target.Adapter, target.Id, true,
                "read_only_schema_observed", status, count);
        }
        catch (OperationCanceledException)
        {
            return Failure(target, cancellationToken.IsCancellationRequested
                ? "cancelled" : "timed_out");
        }
        catch (JsonException)
        {
            return Failure(target, "invalid_json");
        }
        catch (HttpRequestException)
        {
            return Failure(target, "transport_error");
        }
        catch (IOException)
        {
            return Failure(target, "response_io_error");
        }
    }
}
