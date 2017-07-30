// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;

namespace IdentityServer4.AccessTokenValidation
{
    public class CombinedAuthenticationOptions :
        IPostConfigureOptions<OAuth2IntrospectionOptions>,
        IPostConfigureOptions<JwtBearerOptions>
    {
        static Func<HttpRequest, string> _tokenRetriever = request => request.HttpContext.Items["idsrv4:tokenvalidation:token"] as string;

        public string AuthenticationScheme { get; set; }
        public Func<HttpRequest, string> TokenRetriever { get; set; }

        public Action<OAuth2IntrospectionOptions> IntrospectionOptions { get; set; }
        public Action<JwtBearerOptions> JwtBearerOptions { get; set; }
        public ScopeValidationOptions ScopeValidationOptions { get; set; }
       // public NopAuthenticationOptions PassThruOptions { get; set; }

        public static CombinedAuthenticationOptions FromIdentityServerAuthenticationOptions(string AuthenticationScheme, IdentityServerAuthenticationOptions options)
        {
            var combinedOptions = new CombinedAuthenticationOptions()
            {
                TokenRetriever = options.TokenRetriever,
                AuthenticationScheme = AuthenticationScheme,

                //PassThruOptions = new NopAuthenticationOptions()
                //{
                //    AuthenticationScheme = options.AuthenticationScheme,
                //    AutomaticAuthenticate = options.AutomaticAuthenticate,
                //    AutomaticChallenge = options.AutomaticChallenge
                //}
            };
            
            switch (options.SupportedTokens)
            {
                case SupportedTokens.Jwt:
                    combinedOptions.JwtBearerOptions = (jwt)=>ConfigureJwt(options,jwt);
                    break;
                case SupportedTokens.Reference:
                    combinedOptions.IntrospectionOptions =(introspectionOptions)=> ConfigureIntrospection(options, introspectionOptions);
                    break;
                case SupportedTokens.Both:
                    combinedOptions.JwtBearerOptions = (jwt)=>ConfigureJwt(options,jwt);
                    combinedOptions.IntrospectionOptions = (introspectionOptions) =>ConfigureIntrospection(options, introspectionOptions);
                    break;
                default:
                    throw new Exception("SupportedTokens has invalid value");
            }

            combinedOptions.ScopeValidationOptions = new ScopeValidationOptions
            {
                AllowedScopes = new string[] { }
            };

            if (options.ValidateScope)
            {
                var allowedScopes = new List<string>();

                if (options.AllowedScopes != null && options.AllowedScopes.Any())
                {
                    allowedScopes.AddRange(options.AllowedScopes);
                }

                if (allowedScopes.Any())
                {
                    combinedOptions.ScopeValidationOptions = new ScopeValidationOptions
                    {
                        AllowedScopes = allowedScopes,
                       // AuthenticationScheme = options.AuthenticationScheme
                    };
                }
            }

            return combinedOptions;
        }

      

        private static void ConfigureIntrospection(IdentityServerAuthenticationOptions options, OAuth2IntrospectionOptions introspectionOptions)
        {
            if (String.IsNullOrWhiteSpace(options.ApiSecret))
            {
                return;
            }

            if (String.IsNullOrWhiteSpace(options.ApiName))
            {
                throw new ArgumentException("ApiName must be configured if ApiSecret is set.");
            }

            //  var introspectionOptions = new OAuth2IntrospectionOptions
            //  {
            // AuthenticationScheme = options.AuthenticationScheme,
            introspectionOptions.Authority = options.Authority;
            introspectionOptions.ClientId = options.ApiName;
            introspectionOptions.ClientSecret = options.ApiSecret;

            //      AutomaticAuthenticate = options.AutomaticAuthenticate,
            //   AutomaticChallenge = options.AutomaticChallenge,

            introspectionOptions.NameClaimType = options.NameClaimType;
            introspectionOptions.RoleClaimType = options.RoleClaimType;

            introspectionOptions.TokenRetriever = _tokenRetriever;
            introspectionOptions.SaveToken = options.SaveToken;

            introspectionOptions.EnableCaching = options.EnableCaching;
            introspectionOptions.CacheDuration = options.CacheDuration;

            introspectionOptions.DiscoveryTimeout = options.BackChannelTimeouts;
            introspectionOptions.IntrospectionTimeout = options.BackChannelTimeouts;
            //};

            if (options.IntrospectionBackChannelHandler != null)
            {
                introspectionOptions.IntrospectionHttpHandler = options.IntrospectionBackChannelHandler;
            }
            if (options.IntrospectionDiscoveryHandler != null)
            {
                introspectionOptions.DiscoveryHttpHandler = options.IntrospectionDiscoveryHandler;
            }

            
        }

        private static void ConfigureJwt(IdentityServerAuthenticationOptions options, JwtBearerOptions jwtOptions)
        {
            //var jwtOptions = new JwtBearerOptions
            //{
            //   AuthenticationScheme = options.AuthenticationScheme,
            jwtOptions.Authority = options.Authority;
            jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

            //   AutomaticAuthenticate = options.AutomaticAuthenticate,
            //  AutomaticChallenge = options.AutomaticChallenge,

            jwtOptions.BackchannelTimeout = options.BackChannelTimeouts;
            jwtOptions.RefreshOnIssuerKeyNotFound = true;

            jwtOptions.SaveToken = options.SaveToken;

            jwtOptions.Events = new JwtBearerEvents
            {
                OnMessageReceived = e =>
                {
                    e.Token = _tokenRetriever(e.Request);
                    return options.JwtBearerEvents.MessageReceived(e);
                },

                OnTokenValidated = e => options.JwtBearerEvents.TokenValidated(e),
                OnAuthenticationFailed = e => options.JwtBearerEvents.AuthenticationFailed(e),
                OnChallenge = e => options.JwtBearerEvents.Challenge(e)
            };
            //};

            if (options.DiscoveryDocumentRefreshInterval.HasValue)
            {
                var parsedUrl = DiscoveryClient.ParseUrl(options.Authority);

                var httpClient = new HttpClient(options.JwtBackChannelHandler ?? new HttpClientHandler())
                {
                    Timeout = options.BackChannelTimeouts,
                    MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB
                };

                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    parsedUrl.discoveryEndpoint,
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(httpClient) { RequireHttps = options.RequireHttpsMetadata })
                {
                    AutomaticRefreshInterval = options.DiscoveryDocumentRefreshInterval.Value
                };

                jwtOptions.ConfigurationManager = manager;
            }

            if (options.JwtBackChannelHandler != null)
            {
                jwtOptions.BackchannelHttpHandler = options.JwtBackChannelHandler;
            }

            // if API name is set, do a strict audience check for
            if (!string.IsNullOrWhiteSpace(options.ApiName) && !options.LegacyAudienceValidation)
            {
                jwtOptions.Audience = options.ApiName;
            }
            else
            {
                // no audience validation, rely on scope checks only
                jwtOptions.TokenValidationParameters.ValidateAudience = false;
            }

            jwtOptions.TokenValidationParameters.NameClaimType = options.NameClaimType;
            jwtOptions.TokenValidationParameters.RoleClaimType = options.RoleClaimType;
            
            if (options.InboundJwtClaimTypeMap != null)
            {
                var handler = new JwtSecurityTokenHandler();
                handler.InboundClaimTypeMap = options.InboundJwtClaimTypeMap;

                jwtOptions.SecurityTokenValidators.Clear();
                jwtOptions.SecurityTokenValidators.Add(handler);
            }

          
        }

        public void PostConfigure(string name, OAuth2IntrospectionOptions options)
        {
            this.IntrospectionOptions(options);
        }

        public void PostConfigure(string name, JwtBearerOptions options)
        {
            this.JwtBearerOptions(options);
        }
    }
}