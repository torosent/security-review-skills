# C# / .NET Security Patterns

> Comprehensive reference for AI-assisted security review of C#/.NET codebases.

## 1 · Insecure Deserialization — CWE-502 (Critical)

| Sink / Pattern | Grep Pattern | Fix |
|---|---|---|
| BinaryFormatter (ALL uses = RCE) | `BinaryFormatter` | Remove entirely. Use `System.Text.Json` |
| SoapFormatter | `SoapFormatter` | Remove. Use `System.Text.Json` |
| NetDataContractSerializer | `NetDataContractSerializer` | Use `DataContractSerializer` with explicit known types |
| ObjectStateFormatter | `ObjectStateFormatter` | Use signed/encrypted ViewState |
| LosFormatter | `LosFormatter` | Use `System.Text.Json` |
| JavaScriptSerializer + type resolver | `JavaScriptSerializer\(.*SimpleTypeResolver` | Use `System.Text.Json` |
| Json.NET unsafe TypeNameHandling | `TypeNameHandling\.(All\|Auto\|Objects\|Arrays)` | Set `TypeNameHandling.None` |
| Newtonsoft with SerializationBinder bypass | `JsonSerializerSettings.*TypeNameHandling(?!.*None)` | Require allow-list `SerializationBinder` |
| EnableUnsafeBinaryFormatterSerialization | `EnableUnsafeBinaryFormatterSerialization` | Remove from project/runtime config |
| DataContractSerializer user types | `DataContractSerializer.*knownTypes.*user\|DataContractSerializer.*Request\.` | Use explicit known-type list, never from user input |
| XmlSerializer user-controlled type | `XmlSerializer\(.*typeof.*user\|XmlSerializer\(.*Request\.` | Hardcode type; never derive from input |

## 2 · SQL Injection — CWE-89 (Critical)

```
SqlCommand\(.*\+|SqlCommand\(.*\$"|\. CommandText\s*=.*\+|\.CommandText\s*=.*\$"
\.ExecuteSqlRaw\(.*\$"|\.ExecuteSqlRaw\(.*\+|\.FromSqlRaw\(.*\$"|\.FromSqlRaw\(.*\+
string\.(Format|Concat).*SELECT|string\.(Format|Concat).*INSERT|string\.(Format|Concat).*UPDATE
\.Query\(.*\$"|\.Query\(.*\+|\.Execute\(.*\$"|\.Execute\(.*\+
DynamicExpressionParser|System\.Linq\.Dynamic
```

| Framework | Unsafe | Safe |
|---|---|---|
| ADO.NET | `cmd.CommandText = "SELECT * WHERE id=" + id` | Use `SqlParameter` |
| EF Core | `FromSqlRaw($"...{input}")` | `FromSqlInterpolated($"...{input}")` |
| Dapper | `conn.Query("..."+input)` | `conn.Query("...@p", new {p=input})` |
| Dynamic LINQ | `Where(userInput)` | Validate/allowlist expressions |

## 3 · Cross-Site Scripting — CWE-79 (High)

```
Html\.Raw\(|@Html\.Raw\(|HtmlHelper\.Raw\(
MarkupString|@\(\(MarkupString\)
\.InnerHtml\s*=|\.InnerText\s*=.*user|Response\.Write\(
JSRuntime.*InvokeAsync.*user|IJSRuntime.*user
htmlContent.*user|WriteLiteral\(.*user
```
**Fix**: Use Razor auto-encoding. Avoid `Html.Raw()` with user data. In Blazor, sanitize before `MarkupString`. Use `HtmlEncoder.Default.Encode()`.

## 4 · XXE — XML External Entity — CWE-611 (High)

```
XmlDocument\(\)(?!.*XmlResolver\s*=\s*null)|new\s+XmlDocument\s*\(
DtdProcessing\s*=\s*DtdProcessing\.Parse|DtdProcessing\.Parse
XmlTextReader\((?!.*DtdProcessing\.Prohibit)
XslCompiledTransform.*EnableScript|XsltSettings\.TrustedXslt
XPathNavigator.*Compile\(.*user|XPathExpression.*user
```
**Fix**: `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`. Disable XSLT scripting.

## 5 · Command Injection — CWE-78 (Critical)

```
Process\.Start\(.*\+|Process\.Start\(.*\$"|Process\.Start\(.*user
ProcessStartInfo.*Arguments.*(\+|\$")
cmd\.exe|/bin/sh|/bin/bash|powershell.*-Command.*user
ProcessStartInfo.*UseShellExecute\s*=\s*true
```
**Fix**: Avoid shell execution. Set `UseShellExecute = false`. Validate/allowlist input. Use argument arrays.

## 6 · Path Traversal — CWE-22 (High)

```
Path\.Combine\(.*Request\.|Path\.Combine\(.*user|Path\.Combine\(.*param
File\.(ReadAll|WriteAll|Open|Delete|Copy|Move).*Request\.|File\..*user
FileStream\(.*Request\.|FileStream\(.*user
IFormFile.*\.FileName(?!.*GetFileName)|\.FileName.*Path\.Combine
Directory\.(GetFiles|GetDirectories|EnumerateFiles).*user
PhysicalFile\(.*Request\.|PhysicalFileProvider\(.*user
Server\.MapPath\(.*Request\.
```
**Fix**: `Path.GetFullPath()` then validate `result.StartsWith(allowedBase)`. Use `Path.GetFileName()` on uploaded filenames. **`Path.Combine` does NOT prevent traversal**.

## 7 · CSRF — CWE-352 (High)

```
\[IgnoreAntiforgeryToken\]|\[IgnoreAntiForgeryToken\]
\[HttpPost\](?!.*\[ValidateAntiForgeryToken\])
SameSiteMode\.None(?!.*Secure\s*=\s*true)|SameSite\s*=\s*SameSiteMode\.None
options\.Cookie\.SameSite\s*=\s*SameSiteMode\.None
```
**Fix**: Add `[ValidateAntiForgeryToken]` on all state-changing actions. Set `SameSite=Strict/Lax`.

## 8 · Auth & JWT — CWE-287 / CWE-306 (Critical)

```
\[AllowAnonymous\]
ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|ValidateLifetime\s*=\s*false
ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false
RequireHttpsMetadata\s*=\s*false|RequireExpirationTime\s*=\s*false
\.Cookie\.HttpOnly\s*=\s*false|\.Cookie\.SecurePolicy\s*=.*None|\.Cookie\.Secure\s*=\s*false
options\.Password\.RequiredLength\s*=\s*[1-5][^0-9]|RequireDigit\s*=\s*false
```
**Review**: Verify `[AllowAnonymous]` is intentional. All JWT validation flags must be `true` in production. Cookies must be `HttpOnly`, `Secure`, `SameSite`.

## 9 · LDAP Injection — CWE-90 (High)

```
DirectorySearcher.*Filter.*(\\+|\$")|DirectoryEntry\(.*(\\+|\$")
SearchRequest\(.*(\\+|\$")|LdapConnection.*Search.*(\\+|\$")
Novell\.Directory\.Ldap.*Filter.*(\\+|\$")
```
**Fix**: Use `LdapFilterEncoder.FilterEncode()` or parameterized LDAP filters.

## 10 · Open Redirect — CWE-601 (Medium)

```
Redirect\(.*Request\.|Redirect\(.*returnUrl|Redirect\(.*url
RedirectToAction\(.*Request\.|LocalRedirect\(.*user
```
**Fix**: Always call `Url.IsLocalUrl(url)` before redirect. Use `LocalRedirect()`.

## 11 · Mass Assignment — CWE-915 (High)

```
TryUpdateModelAsync\((?!.*new\s*\{)|TryUpdateModelAsync\(.*model\s*\)
\[Bind\((?!.*Include)|public\s+async.*Create\(.*Model\s+model\)
UpdateModel\((?!.*includeProperties)
```
**Fix**: Use `[Bind(Include="...")]`, `[BindNever]`, or dedicated ViewModels/DTOs. Never bind directly to domain entities.

## 12 · Insecure Configuration — CWE-16 (Medium)

```
app\.UseDeveloperExceptionPage|UseExceptionHandler.*Developer
"DetailedErrors"\s*:\s*true|DetailedErrors\s*=\s*true
WithOrigins\(.*\*.*\)\.AllowCredentials|AllowAnyOrigin\(\)\.AllowCredentials
AddCors.*AllowAnyOrigin|EnableCors.*\*
options\.MaxRequestBodySize\s*=\s*null|MaxRequestBodySize\s*=\s*long\.MaxValue
UseSwagger\(\)|UseSwaggerUI\(\)|MapSwagger\(\)
options\.SuppressXFrameOptionsHeader\s*=\s*true
```
**Fix**: Conditional `if (env.IsDevelopment())` for DeveloperExceptionPage/Swagger. CORS: specify exact origins. Set request body limits.

## 13 · Weak Cryptography — CWE-327 (Medium)

```
MD5\.Create|MD5CryptoServiceProvider|SHA1\.Create|SHA1Managed|SHA1CryptoServiceProvider
DESCryptoServiceProvider|TripleDES\.|RC2CryptoServiceProvider|RijndaelManaged
CipherMode\.ECB|\.Mode\s*=\s*CipherMode\.ECB
new\s+byte\[\]\s*\{.*\}\s*;\s*.*\.IV\s*=|\.IV\s*=\s*new\s+byte
RNGCryptoServiceProvider|new\s+Random\(\).*password|new\s+Random\(\).*token
ServicePointManager\.ServerCertificateValidationCallback\s*=.*true
RemoteCertificateValidationCallback.*return\s+true
X509CertificateValidationMode\.None
```
**Fix**: Use `SHA256`+, `Aes` with GCM/CBC, `RandomNumberGenerator.GetBytes()`. Never disable cert validation.

## 14 · Logging & Info Disclosure — CWE-532 (Medium)

```
_logger\..*(password|secret|token|apiKey|creditCard|ssn|connectionString)
\.ToString\(\).*Exception.*Response|ex\.(Message|StackTrace).*Response
ProblemDetails.*Detail\s*=.*ex\.|ObjectResult.*ex\.
app\.UseStatusCodePages\(.*ex\.|WriteAsync.*Exception
AddServerHeader\s*=\s*true|Server:.*Kestrel
```
**Fix**: Use structured logging with `[LoggerMessage]`. Redact PII. Return generic error messages. Remove server headers.

## 15 · SignalR — CWE-306 (High)

```
MapHub<.*>\((?!.*RequireAuthorization)|\.MapHub.*(?!.*\[Authorize\])
HubOptions.*MaximumReceiveMessageSize\s*=\s*null
SignalR.*WithOrigins\(.*\*\)|AddSignalR\(\)(?!.*AddAuthorization)
```
**Fix**: Add `[Authorize]` on hubs. Set `MaximumReceiveMessageSize`. Restrict CORS origins.

## 16 · gRPC — CWE-306 (High)

```
GrpcChannel\.ForAddress\(.*http://|Grpc\.Net\.Client.*http://
Credentials\s*=\s*ChannelCredentials\.Insecure|ServerCredentials\.Insecure
MapGrpcService<.*>\((?!.*RequireAuthorization)
MaxReceiveMessageSize\s*=.*int\.MaxValue
```
**Fix**: Use `https://` + TLS. Add `[Authorize]`. Set message size limits.

## 17 · Minimal APIs (ASP.NET Core 6+) — CWE-862 (High)

```
app\.Map(Get|Post|Put|Delete)\((?!.*RequireAuthorization)(?!.*Authorize)
app\.Map(Get|Post|Put|Delete)\((?!.*AddEndpointFilter)
\.AllowAnonymous\(\)
app\.Map.*\(.*\(.*\)\s*=>(?!.*Validate)
```
**Fix**: Chain `.RequireAuthorization()`. Add input validation via endpoint filters or FluentValidation.

## 18 · Blazor-Specific — CWE-200 (Medium)

```
static\s+.*=.*new|CascadingValue.*IsFixed\s*=\s*false
@inject.*IJSRuntime.*\$"|InvokeVoidAsync\(.*user|InvokeAsync<.*>\(.*user
\[Parameter\].*public.*string.*\{.*set|@typeparam.*user
component\.RenderMode.*ServerPrerendered.*secret
```
**Fix**: Avoid shared static state in Server Blazor. Sanitize JS interop args. Use `[EditorRequired]` on parameters.

## 19 · DI / Service Lifetime — CWE-362 (Medium)

```
AddSingleton<.*>.*AddScoped|services\.AddSingleton.*IServiceScopeFactory
GetService\(typeof\(|GetRequiredService.*Scoped.*Singleton
IHttpClientFactory(?!.*AddHttpClient)|new\s+HttpClient\(\)
```
**Fix**: Never inject scoped into singleton. Use `IHttpClientFactory`. Avoid service locator pattern.

## 20 · ReDoS — CWE-1333 (Medium)

```
new\s+Regex\(.*user|new\s+Regex\((?!.*RegexOptions\.\w*Compiled.*Timeout)(?!.*matchTimeout)
Regex\.(Match|Replace|IsMatch)\(.*user(?!.*TimeSpan)
(\.\*\+|\.\+\+|\.\*\*|\(\.\*\)\+|\(\.\+\)\+).*Regex
```
**Fix**: Always set `matchTimeout`. Use `RegexOptions.NonBacktracking` (.NET 7+). Avoid `(.*)+ / (.+)+` patterns.

---

## Quick-Reference: Top Grep Patterns (All Severities)

```bash
# Critical — RCE / Injection
grep -rPn 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatter' .
grep -rPn 'TypeNameHandling\.(All|Auto|Objects|Arrays)' .
grep -rPn 'SqlCommand\(.*(\+|\$")|\. CommandText\s*=.*(\+|\$")' .
grep -rPn 'ExecuteSqlRaw\(.*(\+|\$")|FromSqlRaw\(.*(\+|\$")' .
grep -rPn 'Process\.Start\(.*(\+|\$")' .

# High — Data exposure / Auth bypass
grep -rPn 'Html\.Raw\(|MarkupString' .
grep -rPn 'DtdProcessing\.Parse|XmlDocument\(\)' .
grep -rPn 'ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false' .
grep -rPn '\[AllowAnonymous\]' .
grep -rPn 'Path\.Combine\(.*Request\.' .

# Medium — Crypto / Config / Info leak
grep -rPn 'MD5\.Create|SHA1\.Create|CipherMode\.ECB' .
grep -rPn 'UseDeveloperExceptionPage|DetailedErrors.*true' .
grep -rPn 'new\s+Random\(\).*password|new\s+Random\(\).*token' .
grep -rPn 'ServerCertificateValidationCallback.*true' .
```
