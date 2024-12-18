using System.Diagnostics;


var filePath = "C:\\Users\\Phong.NguyenDoan\\Downloads\\python-3.12.8-amd64.exe";
var sophosPath = @"C:\Program Files\Sophos\Endpoint Defense\sophosinterceptxcli.exe";

using var process = new Process();
process.StartInfo.FileName = sophosPath;
process.StartInfo.Arguments = $"scan --noui --verbose \"{filePath}\"";
process.StartInfo.UseShellExecute = false;
process.StartInfo.RedirectStandardOutput = true;
process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
process.StartInfo.CreateNoWindow = true;
process.Start();

process.WaitForExit();

string output = process.StandardOutput.ReadToEnd();

var isVirus = process.ExitCode != 0;

Console.WriteLine($"ExitCode: {process.ExitCode}, Output: {output}, Is virus: {isVirus}");