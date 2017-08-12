// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;

namespace Microsoft.AspNetCore.Builder
{
    public static class IdentityServerAuthenticationExtensions
    {

        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder)
            => builder.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddIdentityServerAuthentication(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, Action<IdentityServerAuthenticationOptions> configureOptions) =>
            builder.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddIdentityServerAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<IdentityServerAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuth2IntrospectionOptions>, CombinedAuthenticationOptions>(sp=>sp.GetService< CombinedAuthenticationOptions>()));
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, CombinedAuthenticationOptions>(sp => sp.GetService<CombinedAuthenticationOptions>()));
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<IdentityServerAuthenticationOptions>, PostConfigureIdentityServerAuthenticationOptions>());

            //  services.AddSingleton((sp) => Options.Create( sp.GetService<CombinedAuthenticationOptions>().IntrospectionOptions));
            // services.AddSingleton((sp) => Options.Create( sp.GetService<CombinedAuthenticationOptions>().JwtBearerOptions));
            builder.Services.AddSingleton((sp) => CombinedAuthenticationOptions.FromIdentityServerAuthenticationOptions(authenticationScheme,
                sp.GetService<IOptions<IdentityServerAuthenticationOptions>>().Value));

            builder.Services.Configure(configureOptions);

            builder.AddJwtBearer("oidc-jwt-bearer", (o) =>
            {

            });
            builder.AddOAuth2IntrospectionAuthentication("oidc-introspection-bearer");
          //  services.AddJwtBearerAuthentication();
             

            return builder.AddScheme<IdentityServerAuthenticationOptions, IdentityServerAuthenticationHandler>(authenticationScheme, configureOptions);
        }

        //public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app)
        //{
        //    var options = app.ApplicationServices.GetService<IOptions<IdentityServerAuthenticationOptions>>();

        //    app.Validate(options.Value);

        //    var combinedOptions = CombinedAuthenticationOptions.FromIdentityServerAuthenticationOptions(options);
        //    app.UseIdentityServerAuthentication(combinedOptions);

        //    return app;
        //}

        public static IApplicationBuilder UseIdentityServerAuthentication(this IApplicationBuilder app)
        {
            var options = app.ApplicationServices.GetService<CombinedAuthenticationOptions>();
            app.UseMiddleware<IdentityServerAuthenticationMiddleware>(app, options);

            if (options.ScopeValidationOptions.AllowedScopes.Any())
            {
                app.AllowScopes(options.ScopeValidationOptions);
            }

            return app;
        }

        //internal static void Validate(this IApplicationBuilder app, IdentityServerAuthenticationOptions options)
        //{

        //}
    }
}
