using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

var cfg = Cfg.Prs(args);
if (cfg == null)
{
    Console.Error.WriteLine("usage: vso-certwatch <host[,host...]|@file> [--port 443] [--warn 30] [--conc 20] [--tmo 5000] [--json]");
    return 2;
}

var sem = new SemaphoreSlim(cfg.Conc);
var tsk = cfg.Hsts.Select(async h =>
{
    await sem.WaitAsync();
    try { return await Prb.Run(h, cfg); }
    finally { sem.Release(); }
}).ToList();
var res = (await Task.WhenAll(tsk)).OrderBy(r => r.Days ?? int.MinValue).ToList();

if (cfg.Json)
{
    Console.WriteLine(JsonSerializer.Serialize(res, new JsonSerializerOptions { WriteIndented = true }));
}
else
{
    foreach (var r in res)
        Console.WriteLine($"{r.Stat,-8} {r.Hst,-40} {(r.Days.HasValue ? r.Days + "d" : "-"),-7} {r.Proto,-8} {r.Iss}");
}
return res.Any(r => r.Stat != "OK") ? 1 : 0;

record Cfg(List<string> Hsts, int Port, int Warn, int Conc, int Tmo, bool Json)
{
    static readonly Regex Hrx = new(@"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$", RegexOptions.Compiled);

    public static Cfg? Prs(string[] a)
    {
        if (a.Length == 0) return null;
        int port = 443, warn = 30, conc = 20, tmo = 5000;
        bool js = false;
        string src = a[0];
        for (int i = 1; i < a.Length; i++)
        {
            switch (a[i])
            {
                case "--json": js = true; break;
                case "--port" when i + 1 < a.Length && int.TryParse(a[++i], out var v): port = v; break;
                case "--warn" when i + 1 < a.Length && int.TryParse(a[++i], out var v): warn = v; break;
                case "--conc" when i + 1 < a.Length && int.TryParse(a[++i], out var v): conc = v; break;
                case "--tmo" when i + 1 < a.Length && int.TryParse(a[++i], out var v): tmo = v; break;
                default: return null;
            }
        }
        if (port is < 1 or > 65535 || warn is < 0 or > 3650 || conc is < 1 or > 200 || tmo is < 500 or > 30000) return null;
        IEnumerable<string> raw;
        if (src.StartsWith('@'))
        {
            var pth = src[1..];
            if (!File.Exists(pth) || new FileInfo(pth).Length > 1_000_000) return null;
            raw = File.ReadAllLines(pth);
        }
        else raw = src.Split(',');
        var lst = raw.Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0 && !x.StartsWith('#')).Distinct().ToList();
        if (lst.Count == 0 || lst.Count > 5000 || lst.Any(x => !Hrx.IsMatch(x))) return null;
        return new Cfg(lst, port, warn, conc, tmo, js);
    }
}

record Res(string Hst, string Stat, string? Subj, string? Iss, DateTime? Exp, int? Days, string? Sig, string? Proto, string? Errs);

static class Prb
{
    public static async Task<Res> Run(string hst, Cfg cfg)
    {
        try
        {
            using var cts = new CancellationTokenSource(cfg.Tmo);
            using var cl = new TcpClient();
            await cl.ConnectAsync(hst, cfg.Port, cts.Token);
            X509Certificate2? crt = null;
            var pe = SslPolicyErrors.None;
            using var ss = new SslStream(cl.GetStream(), false, (_, c, _, e) =>
            {
                if (c != null) crt = new X509Certificate2(c);
                pe = e;
                return true;
            });
            await ss.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = hst,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            }, cts.Token);
            if (crt == null) return new Res(hst, "ERR", null, null, null, null, null, null, "no cert");
            var exp = crt.NotAfter.ToUniversalTime();
            var days = (int)Math.Floor((exp - DateTime.UtcNow).TotalDays);
            var stat = days < 0 ? "EXPIRED" : pe != SslPolicyErrors.None ? "INVALID" : days <= cfg.Warn ? "WARN" : "OK";
            return new Res(hst, stat, crt.Subject, crt.Issuer, exp, days, crt.SignatureAlgorithm.FriendlyName,
                ss.SslProtocol.ToString(), pe == SslPolicyErrors.None ? null : pe.ToString());
        }
        catch (OperationCanceledException) { return new Res(hst, "ERR", null, null, null, null, null, null, "timeout"); }
        catch (Exception e) { return new Res(hst, "ERR", null, null, null, null, null, null, e.GetType().Name); }
    }
}
