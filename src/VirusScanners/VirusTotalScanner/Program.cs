using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;

string ApiKey = "xxx";

var filePath = "VirusTotalScanner.dll";

var client = new HttpClient();
client.DefaultRequestHeaders.Add("x-apikey", ApiKey);

// https://www.eicar.org/download-anti-malware-testfile/
//using var stream = new MemoryStream(Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));

using var stream = File.OpenRead(filePath);
await ScanFileAsync(client, stream, Path.GetFileName(filePath));


static async Task<string> UploadFileAsync(HttpClient client, Stream stream, string fileName)
{
    using var content = new MultipartFormDataContent
    {
        {
            new StreamContent(stream),
            "file",
            fileName
        }
    };

    var response = await client.PostAsync("https://www.virustotal.com/api/v3/files", content);

    response.EnsureSuccessStatusCode();

    var result = await response.Content.ReadFromJsonAsync<UploadFileResponse>();

    return result!.Data.Id;
}

static async Task<AnalysisResponse> GetAnalysisAsync(HttpClient client, string analysisId)
{
    var response = await client.GetAsync($"https://www.virustotal.com/api/v3/analyses/{analysisId}");

    response.EnsureSuccessStatusCode();

    var result = await response.Content.ReadFromJsonAsync<AnalysisResponse>();

    return result!;
}

static async Task ScanFileAsync(HttpClient client, Stream stream, string fileName)
{
    var analysisId = await UploadFileAsync(client, stream, fileName);

    Console.WriteLine($"Uploaded. AnalysisId = {analysisId}");

    while (true)
    {
        await Task.Delay(3000); // respect rate limits

        var result = await GetAnalysisAsync(client, analysisId);

        var status = result.Data.Attributes.Status;

        if (status == "completed")
        {
            var stats = result.Data.Attributes.Stats!;

            Console.WriteLine("Scan completed:");
            Console.WriteLine($"Malicious: {stats.Malicious}");
            Console.WriteLine($"Suspicious: {stats.Suspicious}");
            Console.WriteLine($"Undetected: {stats.Undetected}");
            Console.WriteLine();

            // Display results from each antivirus software
            var results = result.Data.Attributes.Results;
            if (results != null)
            {
                Console.WriteLine("Antivirus Results:");
                Console.WriteLine(new string('-', 100));

                foreach (var (antivirusName, avResult) in results)
                {
                    var resultText = avResult.Result ?? "clean";
                    var categoryDisplay = avResult.Category switch
                    {
                        "malicious" => "[MALICIOUS]",
                        "suspicious" => "[SUSPICIOUS]",
                        "undetected" => "[CLEAN]",
                        _ => $"[{avResult.Category.ToUpper()}]"
                    };

                    Console.WriteLine($"{categoryDisplay,-15} {antivirusName,-20} v{avResult.EngineVersion,-10} -> {resultText}");
                }
            }

            break;
        }

        Console.WriteLine("Scanning...");
    }
}

// Response models
record UploadFileResponse(
    [property: JsonPropertyName("data")] UploadFileData Data
);

record UploadFileData(
    [property: JsonPropertyName("id")] string Id
);

record AnalysisResponse(
    [property: JsonPropertyName("data")] AnalysisData Data
);

record AnalysisData(
    [property: JsonPropertyName("attributes")] AnalysisAttributes Attributes
);

record AnalysisAttributes(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("stats")] AnalysisStats? Stats,
    [property: JsonPropertyName("results")] Dictionary<string, AntivirusResult>? Results
);

record AnalysisStats(
    [property: JsonPropertyName("malicious")] int Malicious,
    [property: JsonPropertyName("suspicious")] int Suspicious,
    [property: JsonPropertyName("undetected")] int Undetected
);

record AntivirusResult(
    [property: JsonPropertyName("method")] string? Method,
    [property: JsonPropertyName("engine_name")] string EngineName,
    [property: JsonPropertyName("engine_version")] string? EngineVersion,
    [property: JsonPropertyName("engine_update")] string? EngineUpdate,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("result")] string? Result
);