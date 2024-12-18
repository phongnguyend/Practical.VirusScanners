using System.Diagnostics;


var filePath = "C:\\Users\\Phong.NguyenDoan\\Downloads\\python-3.12.8-amd64.exe";
var windowsDefenderPath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";

using var process = new Process();
process.StartInfo.FileName = windowsDefenderPath;
process.StartInfo.Arguments = $"-Scan -ScanType 3 -File \"{filePath}\" -DisableRemediation";
process.StartInfo.UseShellExecute = false;
process.StartInfo.RedirectStandardOutput = true;
process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
process.StartInfo.CreateNoWindow = true;
process.Start();

process.WaitForExit();

string output = process.StandardOutput.ReadToEnd();

var isVirus = process.ExitCode == 2;

Console.WriteLine($"ExitCode: {process.ExitCode}, Output: {output}, Is virus: {isVirus}");