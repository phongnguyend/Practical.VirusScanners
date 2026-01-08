using nClam;

var filePath = "C:\\Users\\Phong.NguyenDoan\\Downloads\\python-3.12.8-amd64.exe";

using var stream = File.OpenRead(filePath);

var clam = new ClamClient("localhost", 3310);
clam.MaxStreamSize = 2147483648; // 2GB

var scanResult = await clam.SendAndScanFileAsync(stream);

switch (scanResult.Result)
{
    case ClamScanResults.Clean:
        Console.WriteLine("The file is clean!");
        break;
    case ClamScanResults.VirusDetected:
        Console.WriteLine("Virus Found!");
        Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
        break;
    case ClamScanResults.Error:
        Console.WriteLine("Woah an error occured! Error: {0}", scanResult.RawResult);
        break;
}