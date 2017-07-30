// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public class PostConfigureIdentityServerAuthenticationOptions : 
        IPostConfigureOptions<IdentityServerAuthenticationOptions>
    {
        private ILoggerFactory _logger;
        public PostConfigureIdentityServerAuthenticationOptions(ILoggerFactory logger)
        {
            _logger = logger;

        }
      

        public void PostConfigure(string name, IdentityServerAuthenticationOptions options)
        {
              if (_logger == null) return;

            var logger = _logger.CreateLogger("IdentityServer4.AccessTokenValidation.Startup");
            if (string.IsNullOrEmpty(options.ApiName) && !options.AllowedScopes.Any())
            {
                logger.LogInformation("Neither an ApiName nor allowed scopes are configured. It is recommended to configure some audience checking.");
            }
        }
    }
}