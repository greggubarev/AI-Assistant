using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private const string AuthUrl = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth";
    private const string ChatUrl = "https://api.giga.chat/v1/chat/completions";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static async Task<int> Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        var authKey = Environment.GetEnvironmentVariable("GIGACHAT_AUTH_KEY");
        if (string.IsNullOrWhiteSpace(authKey))
        {
            var keyFile = Path.Combine(Directory.GetCurrentDirectory(), ".gigachat-auth-key");
            if (File.Exists(keyFile))
                authKey = await File.ReadAllTextAsync(keyFile);
        }

        if (string.IsNullOrWhiteSpace(authKey))
        {
            Console.Error.WriteLine("Укажите ключ в GIGACHAT_AUTH_KEY или в файле .gigachat-auth-key рядом с проектом.");
            return 1;
        }

        var scope = Environment.GetEnvironmentVariable("GIGACHAT_SCOPE") ?? "GIGACHAT_API_PERS";
        var model = Environment.GetEnvironmentVariable("GIGACHAT_MODEL") ?? "GigaChat-2";

        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = ValidateServerCertificate
        };
        using var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };

        try
        {
            var token = await GetAccessTokenAsync(httpClient, authKey.Trim(), scope);
            var history = new List<ChatMessage>();

            Console.WriteLine("Подключено. Введите сообщение или 'выход' для завершения.");
            while (true)
            {
                Console.Write("Вы: ");
                var input = Console.ReadLine();
                if (input is null || input.Trim().Equals("выход", StringComparison.OrdinalIgnoreCase))
                    break;
                if (string.IsNullOrWhiteSpace(input))
                    continue;

                if (DateTimeOffset.UtcNow >= token.ExpiresAt.AddMinutes(-1))
                    token = await GetAccessTokenAsync(httpClient, authKey.Trim(), scope);

                var message = new ChatMessage("user", input.Trim());
                history.Add(message);
                try
                {
                    var answer = await GetAnswerAsync(httpClient, token.Value, model, history);
                    Console.WriteLine($"GigaChat: {answer}\n");
                    history.Add(new ChatMessage("assistant", answer));
                }
                catch
                {
                    history.RemoveAt(history.Count - 1);
                    throw;
                }
            }

            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Ошибка: {ex.Message}");
            if (ex.ToString().Contains("certificate", StringComparison.OrdinalIgnoreCase))
                Console.Error.WriteLine("Для GigaChat установите корневой сертификат НУЦ Минцифры по инструкции сервиса.");
            return 1;
        }
    }

    private static async Task<AccessToken> GetAccessTokenAsync(HttpClient client, string authKey, string scope)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, AuthUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authKey);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Add("RqUID", Guid.NewGuid().ToString());
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["scope"] = scope });

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        EnsureSuccess(response.StatusCode, body, "Получение токена");

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        var value = root.GetProperty("access_token").GetString();
        var expiresAt = root.GetProperty("expires_at").GetInt64();
        if (string.IsNullOrEmpty(value))
            throw new InvalidOperationException("Сервис вернул пустой токен доступа.");

        return new AccessToken(value, DateTimeOffset.FromUnixTimeMilliseconds(expiresAt));
    }

    private static async Task<string> GetAnswerAsync(
        HttpClient client, string accessToken, string model, List<ChatMessage> history)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, ChatUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = JsonContent.Create(new { model, messages = history }, options: JsonOptions);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        EnsureSuccess(response.StatusCode, body, "Ответ GigaChat");

        using var json = JsonDocument.Parse(body);
        var choices = json.RootElement.GetProperty("choices");
        if (choices.GetArrayLength() == 0)
            throw new InvalidOperationException("Сервис вернул ответ без сообщений.");

        var answer = choices[0].GetProperty("message").GetProperty("content").GetString();
        return string.IsNullOrWhiteSpace(answer)
            ? throw new InvalidOperationException("Сервис вернул пустой ответ.")
            : answer;
    }

    private static void EnsureSuccess(HttpStatusCode status, string body, string operation)
    {
        if ((int)status is >= 200 and < 300)
            return;

        var details = body.Length > 1000 ? body[..1000] : body;
        throw new HttpRequestException($"{operation}: HTTP {(int)status}. {details}");
    }

    private static bool ValidateServerCertificate(
        HttpRequestMessage request, X509Certificate2? certificate, X509Chain? _, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
            return true;
        if (certificate is null || errors != SslPolicyErrors.RemoteCertificateChainErrors ||
            request.RequestUri?.Host is not ("ngw.devices.sberbank.ru" or "api.giga.chat"))
            return false;

        var rootPath = Path.Combine(AppContext.BaseDirectory, "certs", "russian_trusted_root_ca_pem.crt");
        using var root = X509CertificateLoader.LoadCertificateFromFile(rootPath);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        return chain.Build(certificate);
    }

    private sealed record AccessToken(string Value, DateTimeOffset ExpiresAt);
    private sealed record ChatMessage(string Role, string Content);
}
