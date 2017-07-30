// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


//using IdentityServer4.AccessTokenValidation.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.AccessTokenValidation
{
    public class IdentityServerAuthenticationMiddleware
    {
        const string _tokenKey = "idsrv4:tokenvalidation:token";

        private readonly ILogger<IdentityServerAuthenticationMiddleware> _logger;
        private readonly CombinedAuthenticationOptions _options;
        private readonly RequestDelegate _next;

        public IdentityServerAuthenticationMiddleware(RequestDelegate next, IApplicationBuilder app, CombinedAuthenticationOptions options, ILogger<IdentityServerAuthenticationMiddleware> logger)
        {
            _options = options;
            _logger = logger;
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var result = await context.AuthenticateAsync(_options.AuthenticationScheme);
            if (result.Succeeded)
            {
                context.User = result.Principal;

            }
            //else
            //{

            //    context.Response.StatusCode = 401;
            //    context.Response.Headers.Add("WWW-Authenticate", new[] { $"Bearer error=\"{result.Failure.Message}\"" });
            //}
            await _next(context);
        }
    }
}