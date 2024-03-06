/*
 1. Create an endpoint which creates the cookie.
 2. Create an endpoint which retrieves data from cookie and send it in the response.
 3. Create a middleware for repeated work of retrieval data from cookie.
 */
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using System.IO.Pipes;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/cookie", (context) =>
{
    context.Response.Headers.SetCookie = "authCookie=username:batman";
    return context.Response.WriteAsync("cookie set");
});

app.MapGet("/fetchCookie", context =>
{
    var cookies = context.Request.Cookies
        .FirstOrDefault(x => x.Key.Equals("authCookie"
            , StringComparison.OrdinalIgnoreCase));

    var annonymous = new { key = cookies.Key, value = cookies.Value };

    return context.Response
        .WriteAsync($"key:- {annonymous.key}" +
        $", value :- {annonymous.value}");
});
app.MapGet("/", () => "Hello World!");

app.Run();
