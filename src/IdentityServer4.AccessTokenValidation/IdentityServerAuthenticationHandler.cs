// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using IdentityServer4.AccessTokenValidation;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public class IdentityServerAuthenticationHandler : AuthenticationHandler<IdentityServerAuthenticationOptions>
    {
        const string _tokenKey = "idsrv4:tokenvalidation:token";

        private readonly CombinedAuthenticationOptions _options;
        private readonly ILogger<IdentityServerAuthenticationHandler> _logger;

        public IdentityServerAuthenticationHandler(
            IOptionsMonitor<IdentityServerAuthenticationOptions> options,
            ILoggerFactory logger, 
            UrlEncoder encoder,
            ISystemClock clock,
            CombinedAuthenticationOptions combinedOptions) 
            : base(options, logger, encoder, clock)
        {
            _options = combinedOptions;
            _logger = logger.CreateLogger<IdentityServerAuthenticationHandler>();
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {

            var token = _options.TokenRetriever(Context.Request);
            bool removeToken = false;


            try
            {
                if (token != null)
                {
                    removeToken = true;

                    Context.Items.Add(_tokenKey, token);

                    // seems to be a JWT
                    if (token.Contains('.'))
                    {
                        // see if local validation is setup
                        var result = await Context.AuthenticateAsync(this.Scheme.Name+ "-oidc-jwt-bearer");
                        if (!result.None)
                            return result;

                        // otherwise use introspection endpoint
                        result = await Context.AuthenticateAsync(this.Scheme.Name + "-oidc-introspection-bearer");
                        if (!result.None)
                            return result;

                        _logger.LogWarning("No validator configured for JWT token");
                    }
                    else
                    {
                        // use introspection endpoint
                        var result = await Context.AuthenticateAsync(this.Scheme.Name + "-oidc-introspection-bearer");
                        if (!result.None)
                            return result;

                        _logger.LogWarning("No validator configured for reference token. Ensure ApiName and ApiSecret have been configured to use introspection.");
                    }
                }

                return AuthenticateResult.Fail("No token found.");
            }
            finally
            {
                if (removeToken)
                {
                    Context.Items.Remove(_tokenKey);
                }
            }

        

           

        


        }
    }
}