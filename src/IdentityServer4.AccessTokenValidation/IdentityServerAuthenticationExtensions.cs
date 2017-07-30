// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.AccessTokenValidation;
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

        public static IServiceCollection AddIdentityServerAuthentication(this IServiceCollection services) => services.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme);

        public static IServiceCollection AddIdentityServerAuthentication(this IServiceCollection services, string authenticationScheme) => services.AddIdentityServerAuthentication(authenticationScheme, configureOptions: null);

        public static IServiceCollection AddIdentityServerAuthentication(this IServiceCollection services, Action<IdentityServerAuthenticationOptions> configureOptions) =>
            services.AddIdentityServerAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static IServiceCollection AddIdentityServerAuthentication(this IServiceCollection services, string authenticationScheme, Action<IdentityServerAuthenticationOptions> configureOptions)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuth2IntrospectionOptions>, CombinedAuthenticationOptions>(sp=>sp.GetService< CombinedAuthenticationOptions>()));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, CombinedAuthenticationOptions>(sp => sp.GetService<CombinedAuthenticationOptions>()));

            services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<IdentityServerAuthenticationOptions>, PostConfigureIdentityServerAuthenticationOptions>());

          //  services.AddSingleton((sp) => Options.Create( sp.GetService<CombinedAuthenticationOptions>().IntrospectionOptions));
           // services.AddSingleton((sp) => Options.Create( sp.GetService<CombinedAuthenticationOptions>().JwtBearerOptions));
            services.AddSingleton((sp) => CombinedAuthenticationOptions.FromIdentityServerAuthenticationOptions(authenticationScheme,
                sp.GetService<IOptions<IdentityServerAuthenticationOptions>>().Value));

            services.Configure(configureOptions);

            services.AddOAuth2IntrospectionAuthentication("oidc-introspection-bearer");
            services.AddJwtBearerAuthentication("oidc-jwt-bearer",(o)=> {

            });
             

            return services.AddScheme<IdentityServerAuthenticationOptions, IdentityServerAuthenticationHandler>(authenticationScheme, configureOptions);
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
