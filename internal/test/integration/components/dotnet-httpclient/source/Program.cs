using System.Net;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// One handler for the process lifetime exercises the connection pool across
// incoming requests, including when a previous SendAsync was cancelled.
using var handler = new SocketsHttpHandler
{
    MaxConnectionsPerServer = 8,
    SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true }
};
using var client = new HttpClient(handler);
var proxy = Environment.GetEnvironmentVariable("PROXY_URL") ?? "https://proxy:8443";

app.MapGet("/health", () => "ready");
app.MapGet("/send/{id}", async (string id, HttpContext context) =>
{
    // Force an async continuation before starting the outbound request.
    await Task.Delay(10, context.RequestAborted);
    using var request = new HttpRequestMessage(HttpMethod.Get, $"{proxy}/case/{id}")
    {
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };
    if (context.Request.Query.TryGetValue("owned", out var owned))
        request.Headers.TryAddWithoutValidation("traceparent", owned.ToString());

    using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
    if (context.Request.Query.ContainsKey("cancel"))
    {
        // Wait until the proxy has received this request before cancelling it.
        var pending = client.SendAsync(request, cancellation.Token);
        try
        {
            for (var attempt = 0; attempt < 200; attempt++)
            {
                using var seen = await client.GetAsync($"{proxy}/seen/{id}", context.RequestAborted);
                if (seen.IsSuccessStatusCode)
                    break;
                await Task.Delay(10, context.RequestAborted);
            }
            cancellation.Cancel();
            using var unexpected = await pending;
            return Results.Problem("SendAsync completed before cancellation");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return Results.StatusCode(StatusCodes.Status204NoContent);
        }
    }

    using var response = await client.SendAsync(request, cancellation.Token);
    response.EnsureSuccessStatusCode();
    if (response.Version != HttpVersion.Version11)
        return Results.Problem("Expected HTTP/1.1");
    return Results.Json(new
    {
        downstream = JsonSerializer.Deserialize<JsonElement>(await response.Content.ReadAsStringAsync()),
        runtime_traceparents = request.Headers.TryGetValues("traceparent", out var values)
            ? values.ToArray() : Array.Empty<string>()
    });
});

app.Run();
